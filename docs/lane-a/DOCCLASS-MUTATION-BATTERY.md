# DocClass routing: mutation battery

NOT DEPLOYABLE ON ITS OWN, like the rest of this lane.


Each mutation is applied to the tree that this commit contains, one at a time,
and the NAMED covering test is run BY NAME (`-- --exact <test>`), under
`CARGO_INCREMENTAL=0`. A kill requires that test to appear in libtest's output
AND to have failed, so "survived" means the named test passed with the mutation
in place rather than that some other test happened to fail. A mutation whose
anchor does not resolve exactly once aborts the whole run before anything is
applied; one that does not compile, and one whose covering test does not appear,
are separate categories that never count as kills. Restoration happens in a
`finally` and on SIGINT/SIGTERM, and every restore is checked against the pre-run
hash.

Whole-tree text scanning for leftover replacements is diagnostic only. A
replacement is usable as a residue marker only if it does not already occur in
the pristine tree; 24 of these do occur there -- outright deletions,
and strings such as `Ok(true)`, `Ok(())` and `.map_err(StateError::Storage)` --
so finding them proves nothing. The final evidence is 88 mutations total,
64 scanned specifically by text, and 24 covered by exact file
hashes alone. The authoritative residue check for all 88 is the pre/post
hash of every mutated file, printed at the end of this document.


## Pre-run file hashes

```
  5925bf4e0ab72b758cd6667dddcf928e80366485f60f49e014fb9ad7ef0bd514  crates/state/src/docclass_view.rs
  a153540882e95497a56046b09d968dae5a30061ea414dc59b49cf1a6b2a9a3ef  crates/state/src/docclass_executor.rs
  2f2955959f43c6a5aa554a6dece59752116fed8aa9cfe1503ec86ea17fb02335  crates/state/src/executor.rs
  d2f2828d06848257b7eb16bebb7e14d30a2a1c9cb40466dd16db2e04341779eb  crates/storage/src/docclass_store.rs
```


## The 88 mutations


### `crates/state/src/docclass_view.rs`


#### A1 identity-root read sees nothing

* occurrences checked before applying: **1** (expected 1)
* covering test: `an_identity_created_earlier_in_the_block_accepts_a_key` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `8f44295be9c0c51d` -> replacement `aa337c2c2dee3515`
* verdict: **KILLED**

Anchor:
```rust
        match view
            .get(cf::DOCCLASS_IDENTITY_ROOTS, identity_root_key(identity_id))
            .map_err(StateError::Storage)?
        {
```
Replacement:
```rust
        match None::<Vec<u8>> {
```
Printed by libtest while mutated:
```
test an_identity_created_earlier_in_the_block_accepts_a_key ... FAILED
```

#### A2 eligibility read sees nothing

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_credential_issued_earlier_in_the_block_can_be_revoked` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `d848f4508f0bcab4` -> replacement `aa337c2c2dee3515`
* verdict: **KILLED**

Anchor:
```rust
        match view
            .get(cf::DOCCLASS_ELIGIBILITY, eligibility_key(credential_id))
            .map_err(StateError::Storage)?
        {
```
Replacement:
```rust
        match None::<Vec<u8>> {
```
Printed by libtest while mutated:
```
test a_credential_issued_earlier_in_the_block_can_be_revoked ... FAILED
```

#### A3 credential read sees nothing

* occurrences checked before applying: **1** (expected 1)
* covering test: `corrupt_rows_error_through_dispatch_with_exactly_this_staged` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `d443f0e7a1bf13c7` -> replacement `aa337c2c2dee3515`
* verdict: **KILLED**

Anchor:
```rust
        match view
            .get(cf::DOCCLASS_CREDENTIALS, credential_key(credential_id))
            .map_err(StateError::Storage)?
        {
```
Replacement:
```rust
        match None::<Vec<u8>> {
```
Printed by libtest while mutated:
```
test corrupt_rows_error_through_dispatch_with_exactly_this_staged ... FAILED
```

#### A4 issuer read sees nothing

* occurrences checked before applying: **1** (expected 1)
* covering test: `an_issuer_registered_earlier_in_the_block_can_issue_a_credential` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `5baa093a8caa26cd` -> replacement `aa337c2c2dee3515`
* verdict: **KILLED**

Anchor:
```rust
        match view
            .get(cf::DOCCLASS_ISSUERS, docclass_issuer_key(address))
            .map_err(StateError::Storage)?
        {
```
Replacement:
```rust
        match None::<Vec<u8>> {
```
Printed by libtest while mutated:
```
test an_issuer_registered_earlier_in_the_block_can_issue_a_credential ... FAILED
```

#### A5 subject index (identity shape) read sees nothing

* occurrences checked before applying: **1** (expected 1)
* covering test: `all_three_indexes_accumulate_within_one_block` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `cf49e8acdda404fc` -> replacement `22a2b30e75d367e0`
* verdict: **KILLED**

Anchor:
```rust
        match view
            .get(
                cf::DOCCLASS_SUBJECT_INDEX,
                subject_index_key(subject_commitment),
            )
            .map_err(StateError::Storage)?
        {
            Some(bytes) => decode_subject_identity_index(&bytes).map_err(StateError::Storage),
```
Replacement:
```rust
        match None::<Vec<u8>> {
            Some(bytes) => decode_subject_identity_index(&bytes).map_err(StateError::Storage),
```
Printed by libtest while mutated:
```
test all_three_indexes_accumulate_within_one_block ... FAILED
```

#### A6 subject index (credential shape) read sees nothing

* occurrences checked before applying: **1** (expected 1)
* covering test: `all_three_indexes_accumulate_within_one_block` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `2fc6daea4bfecca2` -> replacement `082a9727c4d09958`
* verdict: **KILLED**

Anchor:
```rust
        match view
            .get(
                cf::DOCCLASS_SUBJECT_INDEX,
                subject_index_key(subject_commitment),
            )
            .map_err(StateError::Storage)?
        {
            Some(bytes) => decode_subject_credential_index(&bytes).map_err(StateError::Storage),
```
Replacement:
```rust
        match None::<Vec<u8>> {
            Some(bytes) => decode_subject_credential_index(&bytes).map_err(StateError::Storage),
```
Printed by libtest while mutated:
```
test all_three_indexes_accumulate_within_one_block ... FAILED
```

#### A7 issuer index read sees nothing

* occurrences checked before applying: **1** (expected 1)
* covering test: `all_three_indexes_accumulate_within_one_block` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `de7b400030095ee2` -> replacement `aa337c2c2dee3515`
* verdict: **KILLED**

Anchor:
```rust
        match view
            .get(cf::DOCCLASS_ISSUER_INDEX, issuer_index_key(issuer))
            .map_err(StateError::Storage)?
        {
```
Replacement:
```rust
        match None::<Vec<u8>> {
```
Printed by libtest while mutated:
```
test all_three_indexes_accumulate_within_one_block ... FAILED
```

#### A8 revocation scan sees nothing

* occurrences checked before applying: **1** (expected 1)
* covering test: `suspend_then_reactivate_in_one_block_reactivates_the_credential` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `9994e0492da6c31d` -> replacement `d77f967e69ab100b`
* verdict: **KILLED**

Anchor:
```rust
        let mut records = Vec::new();
        for entry in view
            .prefix_iter(cf::DOCCLASS_REVOCATIONS, credential_id)
            .map_err(StateError::Storage)?
        {
```
Replacement:
```rust
        let mut records = Vec::new();
        for entry in Vec::new().into_iter().chain(view
            .prefix_iter(cf::DOCCLASS_REVOCATIONS, credential_id)
            .map_err(StateError::Storage)?
            .take(0))
        {
```
Printed by libtest while mutated:
```
test suspend_then_reactivate_in_one_block_reactivates_the_credential ... FAILED
```

#### B1 identity_root exists always answers absent

* occurrences checked before applying: **1** (expected 1)
* covering test: `every_duplicate_guard_reads_the_candidate` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `5fd6f1af0ae1b3c9` -> replacement `ceef76dedd7ea878`
* verdict: **KILLED**

Anchor:
```rust
        view.contains(cf::DOCCLASS_IDENTITY_ROOTS, identity_root_key(identity_id))
            .map_err(StateError::Storage)
```
Replacement:
```rust
        Ok(false)
```
Printed by libtest while mutated:
```
test every_duplicate_guard_reads_the_candidate ... FAILED
```

#### B5 identity_root exists always answers present

* occurrences checked before applying: **1** (expected 1)
* covering test: `an_identity_created_earlier_in_the_block_accepts_a_key` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `5fd6f1af0ae1b3c9` -> replacement `2eb902403e286446`
* verdict: **KILLED**

Anchor:
```rust
        view.contains(cf::DOCCLASS_IDENTITY_ROOTS, identity_root_key(identity_id))
            .map_err(StateError::Storage)
```
Replacement:
```rust
        Ok(true)
```
Printed by libtest while mutated:
```
test an_identity_created_earlier_in_the_block_accepts_a_key ... FAILED
```

#### B2 eligibility exists always answers absent

* occurrences checked before applying: **1** (expected 1)
* covering test: `every_duplicate_guard_reads_the_candidate` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `93028f5a92338e4d` -> replacement `ceef76dedd7ea878`
* verdict: **KILLED**

Anchor:
```rust
        view.contains(cf::DOCCLASS_ELIGIBILITY, eligibility_key(credential_id))
            .map_err(StateError::Storage)
```
Replacement:
```rust
        Ok(false)
```
Printed by libtest while mutated:
```
test every_duplicate_guard_reads_the_candidate ... FAILED
```

#### B6 eligibility exists always answers present

* occurrences checked before applying: **1** (expected 1)
* covering test: `an_issuer_registered_earlier_in_the_block_can_issue_a_credential` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `93028f5a92338e4d` -> replacement `2eb902403e286446`
* verdict: **KILLED**

Anchor:
```rust
        view.contains(cf::DOCCLASS_ELIGIBILITY, eligibility_key(credential_id))
            .map_err(StateError::Storage)
```
Replacement:
```rust
        Ok(true)
```
Printed by libtest while mutated:
```
test an_issuer_registered_earlier_in_the_block_can_issue_a_credential ... FAILED
```

#### B3 credential exists always answers absent

* occurrences checked before applying: **1** (expected 1)
* covering test: `every_duplicate_guard_reads_the_candidate` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `1de230006c398dc2` -> replacement `ceef76dedd7ea878`
* verdict: **KILLED**

Anchor:
```rust
        view.contains(cf::DOCCLASS_CREDENTIALS, credential_key(credential_id))
            .map_err(StateError::Storage)
```
Replacement:
```rust
        Ok(false)
```
Printed by libtest while mutated:
```
test every_duplicate_guard_reads_the_candidate ... FAILED
```

#### B7 credential exists always answers present

* occurrences checked before applying: **1** (expected 1)
* covering test: `every_duplicate_guard_reads_the_candidate` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `1de230006c398dc2` -> replacement `2eb902403e286446`
* verdict: **KILLED**

Anchor:
```rust
        view.contains(cf::DOCCLASS_CREDENTIALS, credential_key(credential_id))
            .map_err(StateError::Storage)
```
Replacement:
```rust
        Ok(true)
```
Printed by libtest while mutated:
```
test every_duplicate_guard_reads_the_candidate ... FAILED
```

#### B4 issuer exists always answers absent

* occurrences checked before applying: **1** (expected 1)
* covering test: `every_duplicate_guard_reads_the_candidate` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `c6ce2002b211f3b0` -> replacement `ceef76dedd7ea878`
* verdict: **KILLED**

Anchor:
```rust
        view.contains(cf::DOCCLASS_ISSUERS, docclass_issuer_key(address))
            .map_err(StateError::Storage)
```
Replacement:
```rust
        Ok(false)
```
Printed by libtest while mutated:
```
test every_duplicate_guard_reads_the_candidate ... FAILED
```

#### B8 issuer exists always answers present

* occurrences checked before applying: **1** (expected 1)
* covering test: `an_issuer_registered_earlier_in_the_block_can_issue_a_credential` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `c6ce2002b211f3b0` -> replacement `2eb902403e286446`
* verdict: **KILLED**

Anchor:
```rust
        view.contains(cf::DOCCLASS_ISSUERS, docclass_issuer_key(address))
            .map_err(StateError::Storage)
```
Replacement:
```rust
        Ok(true)
```
Printed by libtest while mutated:
```
test an_issuer_registered_earlier_in_the_block_can_issue_a_credential ... FAILED
```

#### C1 identity put omits its subject-index entry

* occurrences checked before applying: **1** (expected 1)
* covering test: `all_three_indexes_accumulate_within_one_block` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `e4866e3348ae6fb3` -> replacement `bac92e38a4a1ebb9`
* verdict: **KILLED**

Anchor:
```rust
        Self::v_add_to_subject_identity_index(
            view,
            &identity.subject_commitment,
            &identity.identity_id,
            DocSubcode::IdentityRoot,
        )
```
Replacement:
```rust
        let _ = identity.subject_commitment;
        Ok(())
```
Printed by libtest while mutated:
```
test all_three_indexes_accumulate_within_one_block ... FAILED
```

#### C2 identity put omits the primary row

* occurrences checked before applying: **1** (expected 1)
* covering test: `an_identity_created_earlier_in_the_block_accepts_a_key` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `83f1792968a13a75` -> replacement `e3b0c44298fc1c14`
* verdict: **KILLED**

Anchor:
```rust
        let bytes = encode_identity_root(identity).map_err(StateError::Storage)?;
        view.put(
            cf::DOCCLASS_IDENTITY_ROOTS,
            identity_root_key(&identity.identity_id),
            &bytes,
        )
        .map_err(StateError::Storage)?;
```
Replacement:
```rust
(deleted)
```
Printed by libtest while mutated:
```
test an_identity_created_earlier_in_the_block_accepts_a_key ... FAILED
```

#### C3 eligibility put omits its subject-index entry

* occurrences checked before applying: **1** (expected 1)
* covering test: `all_three_indexes_accumulate_within_one_block` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `e77b62a4c395d26f` -> replacement `e3b0c44298fc1c14`
* verdict: **KILLED**

Anchor:
```rust
        Self::v_add_to_subject_credential_index(
            view,
            &attestation.subject_commitment,
            &attestation.credential_id,
        )?;
```
Replacement:
```rust
(deleted)
```
Printed by libtest while mutated:
```
test all_three_indexes_accumulate_within_one_block ... FAILED
```

#### C4 eligibility put omits its issuer-index entry

* occurrences checked before applying: **1** (expected 1)
* covering test: `all_three_indexes_accumulate_within_one_block` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `c8b9450ac69da2d3` -> replacement `5071c6e922d64e3c`
* verdict: **KILLED**

Anchor:
```rust
        Self::v_add_to_issuer_credential_index(
            view,
            &attestation.issuer,
            &attestation.credential_id,
        )
```
Replacement:
```rust
        Ok(())
```
Printed by libtest while mutated:
```
test all_three_indexes_accumulate_within_one_block ... FAILED
```

#### C5 eligibility put omits the primary row

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_credential_issued_earlier_in_the_block_can_be_revoked` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `d447905b49ba7c67` -> replacement `e3b0c44298fc1c14`
* verdict: **KILLED**

Anchor:
```rust
        let bytes = encode_eligibility(attestation).map_err(StateError::Storage)?;
        view.put(
            cf::DOCCLASS_ELIGIBILITY,
            eligibility_key(&attestation.credential_id),
            &bytes,
        )
        .map_err(StateError::Storage)?;
```
Replacement:
```rust
(deleted)
```
Printed by libtest while mutated:
```
test a_credential_issued_earlier_in_the_block_can_be_revoked ... FAILED
```

#### C6 credential put omits its subject-index entry

* occurrences checked before applying: **1** (expected 1)
* covering test: `published_docclass_bytes_match_independently_built_keys_and_values` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `56bf3d1d8f804039` -> replacement `e3b0c44298fc1c14`
* verdict: **KILLED**

Anchor:
```rust
        Self::v_add_to_subject_credential_index(
            view,
            &credential.subject_commitment,
            &credential.credential_id,
        )?;
```
Replacement:
```rust
(deleted)
```
Printed by libtest while mutated:
```
test published_docclass_bytes_match_independently_built_keys_and_values ... FAILED
```

#### C7 credential put omits its issuer-index entry

* occurrences checked before applying: **1** (expected 1)
* covering test: `all_three_indexes_accumulate_within_one_block` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `a5ec03ebfc6f204e` -> replacement `5071c6e922d64e3c`
* verdict: **KILLED**

Anchor:
```rust
        Self::v_add_to_issuer_credential_index(view, &credential.issuer, &credential.credential_id)
```
Replacement:
```rust
        Ok(())
```
Printed by libtest while mutated:
```
test all_three_indexes_accumulate_within_one_block ... FAILED
```

#### C8 credential put omits the primary row

* occurrences checked before applying: **1** (expected 1)
* covering test: `every_duplicate_guard_reads_the_candidate` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `5809d8505d56b67f` -> replacement `e3b0c44298fc1c14`
* verdict: **KILLED**

Anchor:
```rust
        let bytes = encode_credential(credential).map_err(StateError::Storage)?;
        view.put(
            cf::DOCCLASS_CREDENTIALS,
            credential_key(&credential.credential_id),
            &bytes,
        )
        .map_err(StateError::Storage)?;
```
Replacement:
```rust
(deleted)
```
Printed by libtest while mutated:
```
test every_duplicate_guard_reads_the_candidate ... FAILED
```

#### C9 revocation record is never written

* occurrences checked before applying: **1** (expected 1)
* covering test: `suspend_then_reactivate_in_one_block_reactivates_the_credential` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `f84ca7066a768142` -> replacement `7795903e362d5eb0`
* verdict: **KILLED**

Anchor:
```rust
        let key = revocation_key(&record.credential_id, record.revoked_at_height);
        let bytes = encode_revocation_record(record).map_err(StateError::Storage)?;
        view.put(cf::DOCCLASS_REVOCATIONS, &key, &bytes)
            .map_err(StateError::Storage)
```
Replacement:
```rust
        let _ = (record, encode_revocation_record(record));
        Ok(())
```
Printed by libtest while mutated:
```
test suspend_then_reactivate_in_one_block_reactivates_the_credential ... FAILED
```

#### C10 issuer row is never written

* occurrences checked before applying: **1** (expected 1)
* covering test: `an_issuer_registered_earlier_in_the_block_can_issue_a_credential` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `abd12b93c501e889` -> replacement `4fa8538de2f2e16e`
* verdict: **KILLED**

Anchor:
```rust
        let bytes = encode_docclass_issuer(issuer).map_err(StateError::Storage)?;
        view.put(
            cf::DOCCLASS_ISSUERS,
            docclass_issuer_key(&issuer.address),
            &bytes,
        )
        .map_err(StateError::Storage)
```
Replacement:
```rust
        let _ = encode_docclass_issuer(issuer);
        Ok(())
```
Printed by libtest while mutated:
```
test an_issuer_registered_earlier_in_the_block_can_issue_a_credential ... FAILED
```

#### C11 event row is never written

* occurrences checked before applying: **1** (expected 1)
* covering test: `every_docclass_event_in_a_block_lands_at_one_key` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `29768d05fdc73c7b` -> replacement `01b718ca031fc2bf`
* verdict: **KILLED**

Anchor:
```rust
        let key = docclass_event_key(block_height, tx_index, event_index);
        let bytes = encode_docclass_event(event).map_err(StateError::Storage)?;
        view.put(cf::DOCCLASS_EVENTS, &key, &bytes)
            .map_err(StateError::Storage)
```
Replacement:
```rust
        let _ = (block_height, tx_index, event_index, encode_docclass_event(event));
        Ok(())
```
Printed by libtest while mutated:
```
test every_docclass_event_in_a_block_lands_at_one_key ... FAILED
```

#### C12 identity subject-index append loses its dedup

* occurrences checked before applying: **1** (expected 1)
* covering test: `an_identity_created_earlier_in_the_block_can_be_deactivated_and_reactivated` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `5e5975d729c6aaa8` -> replacement `e3b0c44298fc1c14`
* verdict: **KILLED**

Anchor:
```rust
        if index.iter().any(|(id, _)| id == credential_id) {
            return Ok(());
        }
```
Replacement:
```rust
(deleted)
```
Printed by libtest while mutated:
```
test an_identity_created_earlier_in_the_block_can_be_deactivated_and_reactivated ... FAILED
```

#### C13 subject credential index append loses its dedup

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_revocation_rewrites_the_row_without_growing_either_index` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `809c6410da5d10f3` -> replacement `b4a798000f955791`
* verdict: **KILLED**

Anchor:
```rust
        let mut index = Self::v_get_subject_credential_ids(view, subject_commitment)?;
        if index.contains(credential_id) {
            return Ok(());
        }
```
Replacement:
```rust
        let mut index = Self::v_get_subject_credential_ids(view, subject_commitment)?;
```
Printed by libtest while mutated:
```
test a_revocation_rewrites_the_row_without_growing_either_index ... FAILED
```

#### C14 issuer credential index append loses its dedup

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_revocation_rewrites_the_row_without_growing_either_index` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `52e8915e171b51a5` -> replacement `e64dc516ee53c90b`
* verdict: **KILLED**

Anchor:
```rust
        let mut index = Self::v_get_issuer_credential_ids(view, issuer)?;
        if index.contains(credential_id) {
            return Ok(());
        }
```
Replacement:
```rust
        let mut index = Self::v_get_issuer_credential_ids(view, issuer)?;
```
Printed by libtest while mutated:
```
test a_revocation_rewrites_the_row_without_growing_either_index ... FAILED
```

#### D1 eligibility put writes its issuer index before its subject index

* occurrences checked before applying: **1** (expected 1)
* covering test: `corrupt_rows_error_through_dispatch_with_exactly_this_staged` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `cada58c75664b5ee` -> replacement `06694bf579def575`
* verdict: **KILLED**

Anchor:
```rust
        Self::v_add_to_subject_credential_index(
            view,
            &attestation.subject_commitment,
            &attestation.credential_id,
        )?;
        Self::v_add_to_issuer_credential_index(
            view,
            &attestation.issuer,
            &attestation.credential_id,
        )
```
Replacement:
```rust
        Self::v_add_to_issuer_credential_index(
            view,
            &attestation.issuer,
            &attestation.credential_id,
        )?;
        Self::v_add_to_subject_credential_index(
            view,
            &attestation.subject_commitment,
            &attestation.credential_id,
        )
```
Printed by libtest while mutated:
```
test corrupt_rows_error_through_dispatch_with_exactly_this_staged ... FAILED
```

#### D2 credential put writes its indexes before its row

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_credential_refusal_part_way_stages_the_row_and_neither_index` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `5c924bd3b940cc50` -> replacement `0f940ea93b466789`
* verdict: **KILLED**

Anchor:
```rust
        let bytes = encode_credential(credential).map_err(StateError::Storage)?;
        view.put(
            cf::DOCCLASS_CREDENTIALS,
            credential_key(&credential.credential_id),
            &bytes,
        )
        .map_err(StateError::Storage)?;
        Self::v_add_to_subject_credential_index(
            view,
            &credential.subject_commitment,
            &credential.credential_id,
        )?;
        Self::v_add_to_issuer_credential_index(view, &credential.issuer, &credential.credential_id)
```
Replacement:
```rust
        let bytes = encode_credential(credential).map_err(StateError::Storage)?;
        Self::v_add_to_subject_credential_index(
            view,
            &credential.subject_commitment,
            &credential.credential_id,
        )?;
        Self::v_add_to_issuer_credential_index(view, &credential.issuer, &credential.credential_id)?;
        view.put(
            cf::DOCCLASS_CREDENTIALS,
            credential_key(&credential.credential_id),
            &bytes,
        )
        .map_err(StateError::Storage)
```
Printed by libtest while mutated:
```
test a_credential_refusal_part_way_stages_the_row_and_neither_index ... FAILED
```

#### D3 identity put writes its subject index before its row

* occurrences checked before applying: **1** (expected 1)
* covering test: `corrupt_rows_error_through_dispatch_with_exactly_this_staged` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `af8a0c3efcf868c7` -> replacement `630c69dbb8cbcdb3`
* verdict: **KILLED**

Anchor:
```rust
        let bytes = encode_identity_root(identity).map_err(StateError::Storage)?;
        view.put(
            cf::DOCCLASS_IDENTITY_ROOTS,
            identity_root_key(&identity.identity_id),
            &bytes,
        )
        .map_err(StateError::Storage)?;
        Self::v_add_to_subject_identity_index(
            view,
            &identity.subject_commitment,
            &identity.identity_id,
            DocSubcode::IdentityRoot,
        )
```
Replacement:
```rust
        let bytes = encode_identity_root(identity).map_err(StateError::Storage)?;
        Self::v_add_to_subject_identity_index(
            view,
            &identity.subject_commitment,
            &identity.identity_id,
            DocSubcode::IdentityRoot,
        )?;
        view.put(
            cf::DOCCLASS_IDENTITY_ROOTS,
            identity_root_key(&identity.identity_id),
            &bytes,
        )
        .map_err(StateError::Storage)
```
Printed by libtest while mutated:
```
test corrupt_rows_error_through_dispatch_with_exactly_this_staged ... FAILED
```

#### G1 a corrupt row read through decode_identity_root becomes absence

* occurrences checked before applying: **1** (expected 1)
* covering test: `corrupt_rows_error_through_dispatch_with_exactly_this_staged` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `8c758ef442d9f2be` -> replacement `6f441457965ade4b`
* verdict: **KILLED**

Anchor:
```rust
            Some(bytes) => Ok(Some(
                decode_identity_root(&bytes).map_err(StateError::Storage)?,
            )),
```
Replacement:
```rust
            Some(bytes) => Ok(decode_identity_root(&bytes).ok()),
```
Printed by libtest while mutated:
```
test corrupt_rows_error_through_dispatch_with_exactly_this_staged ... FAILED
```

#### G2 a corrupt row read through decode_eligibility becomes absence

* occurrences checked before applying: **1** (expected 1)
* covering test: `corrupt_rows_error_through_dispatch_with_exactly_this_staged` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `335a36529a099ccf` -> replacement `ceb9643896cd7c69`
* verdict: **KILLED**

Anchor:
```rust
            Some(bytes) => Ok(Some(
                decode_eligibility(&bytes).map_err(StateError::Storage)?,
            )),
```
Replacement:
```rust
            Some(bytes) => Ok(decode_eligibility(&bytes).ok()),
```
Printed by libtest while mutated:
```
test corrupt_rows_error_through_dispatch_with_exactly_this_staged ... FAILED
```

#### G3 a corrupt row read through decode_credential becomes absence

* occurrences checked before applying: **1** (expected 1)
* covering test: `corrupt_rows_error_through_dispatch_with_exactly_this_staged` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `7ddd2ad60e134c44` -> replacement `5cb843c114605470`
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
test corrupt_rows_error_through_dispatch_with_exactly_this_staged ... FAILED
```

#### G4 a corrupt row read through decode_docclass_issuer becomes absence

* occurrences checked before applying: **1** (expected 1)
* covering test: `corrupt_rows_error_through_dispatch_with_exactly_this_staged` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `613ae29f8b061bef` -> replacement `940c8dd0a34e9bb7`
* verdict: **KILLED**

Anchor:
```rust
            Some(bytes) => Ok(Some(
                decode_docclass_issuer(&bytes).map_err(StateError::Storage)?,
            )),
```
Replacement:
```rust
            Some(bytes) => Ok(decode_docclass_issuer(&bytes).ok()),
```
Printed by libtest while mutated:
```
test corrupt_rows_error_through_dispatch_with_exactly_this_staged ... FAILED
```

#### G5 a corrupt identity-shaped subject index becomes an empty list

* occurrences checked before applying: **1** (expected 1)
* covering test: `corrupt_rows_error_through_dispatch_with_exactly_this_staged` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `141f8f078cb133a1` -> replacement `c025795e0fd54cd6`
* verdict: **KILLED**

Anchor:
```rust
            Some(bytes) => decode_subject_identity_index(&bytes).map_err(StateError::Storage),
```
Replacement:
```rust
            Some(bytes) => Ok(decode_subject_identity_index(&bytes).unwrap_or_default()),
```
Printed by libtest while mutated:
```
test corrupt_rows_error_through_dispatch_with_exactly_this_staged ... FAILED
```

#### G6 a corrupt credential-shaped subject index becomes an empty list

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_corrupt_credential_shaped_subject_index_errors_the_issue` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `ee0e70d0bda755d3` -> replacement `d774be3ce95347e5`
* verdict: **KILLED**

Anchor:
```rust
            Some(bytes) => decode_subject_credential_index(&bytes).map_err(StateError::Storage),
```
Replacement:
```rust
            Some(bytes) => Ok(decode_subject_credential_index(&bytes).unwrap_or_default()),
```
Printed by libtest while mutated:
```
test a_corrupt_credential_shaped_subject_index_errors_the_issue ... FAILED
```

#### G7 a corrupt issuer index becomes an empty list

* occurrences checked before applying: **1** (expected 1)
* covering test: `corrupt_rows_error_through_dispatch_with_exactly_this_staged` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `7a0982caaa7329ef` -> replacement `f1f6471713395a37`
* verdict: **KILLED**

Anchor:
```rust
            Some(bytes) => decode_issuer_credential_index(&bytes).map_err(StateError::Storage),
```
Replacement:
```rust
            Some(bytes) => Ok(decode_issuer_credential_index(&bytes).unwrap_or_default()),
```
Printed by libtest while mutated:
```
test corrupt_rows_error_through_dispatch_with_exactly_this_staged ... FAILED
```

#### G8 a corrupt revocation row is skipped instead of reported

* occurrences checked before applying: **1** (expected 1)
* covering test: `corrupt_rows_error_through_dispatch_with_exactly_this_staged` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `da999e54da07ba29` -> replacement `2d112f869592fe53`
* verdict: **KILLED**

Anchor:
```rust
                records.push(decode_revocation_record(&value).map_err(StateError::Storage)?);
```
Replacement:
```rust
                if let Ok(r) = decode_revocation_record(&value) {
                    records.push(r);
                }
```
Printed by libtest while mutated:
```
test corrupt_rows_error_through_dispatch_with_exactly_this_staged ... FAILED
```

#### L1 revocation records are sorted oldest first

* occurrences checked before applying: **1** (expected 1)
* covering test: `every_one_of_the_nineteen_operations_runs_against_one_candidate` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `4f7fc4590005d77b` -> replacement `fda555df1ca65585`
* verdict: **KILLED**

Anchor:
```rust
        records.sort_by(|a, b| b.revoked_at_height.cmp(&a.revoked_at_height));
```
Replacement:
```rust
        records.sort_by(|a, b| a.revoked_at_height.cmp(&b.revoked_at_height));
```
Printed by libtest while mutated:
```
test every_one_of_the_nineteen_operations_runs_against_one_candidate ... FAILED
```

#### L2 the revocation key width check is dropped

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_revocation_key_of_the_wrong_width_is_skipped_by_the_candidate_reader` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `1d31892de6c81d28` -> replacement `d1fa31f254bfc526`
* verdict: **KILLED**

Anchor:
```rust
            if key.len() == 40 && &key[..32] == credential_id {
```
Replacement:
```rust
            if &key[..32] == credential_id {
```
Printed by libtest while mutated:
```
test a_revocation_key_of_the_wrong_width_is_skipped_by_the_candidate_reader ... FAILED
```

#### L3 absence of a revocation record reads as Suspended

* occurrences checked before applying: **1** (expected 1)
* covering test: `without_the_suspension_the_same_reactivation_is_refused` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `170be5a8732c688c` -> replacement `285ca00c4a1d1d75`
* verdict: **KILLED**

Anchor:
```rust
            None => Ok(RevocationStatus::Active),
```
Replacement:
```rust
            None => Ok(RevocationStatus::Suspended),
```
Printed by libtest while mutated:
```
test without_the_suspension_the_same_reactivation_is_refused ... FAILED
```

#### J3 can_issue_subcode authorizes everyone

* occurrences checked before applying: **1** (expected 1)
* covering test: `without_the_registration_the_same_issue_is_refused` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `d4548f35e34ad73a` -> replacement `a3d09e12af009f32`
* verdict: **KILLED**

Anchor:
```rust
        match Self::v_get_docclass_issuer(view, address)? {
            Some(issuer) => {
                if !issuer.status.can_issue() {
```
Replacement:
```rust
        let _ = (subcode, jurisdiction);
        if true {
            return Ok(true);
        }
        match Self::v_get_docclass_issuer(view, address)? {
            Some(issuer) => {
                if !issuer.status.can_issue() {
```
Printed by libtest while mutated:
```
test without_the_registration_the_same_issue_is_refused ... FAILED
```

#### J4 can_issue_subcode drops the issuer-type check

* occurrences checked before applying: **1** (expected 1)
* covering test: `an_issuer_can_grant_itself_any_subcode_and_any_stake_by_updating_itself` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `51a04f6b97d22c32` -> replacement `e3b0c44298fc1c14`
* verdict: **KILLED**

Anchor:
```rust
                if !issuer.issuer_type.can_issue(subcode) {
                    return Ok(false);
                }
```
Replacement:
```rust
(deleted)
```
Printed by libtest while mutated:
```
test an_issuer_can_grant_itself_any_subcode_and_any_stake_by_updating_itself ... FAILED
```

#### J5 can_issue_subcode drops the status check

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_suspended_issuer_can_still_revoke_and_update_itself` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `9076218c1764cbae` -> replacement `e3b0c44298fc1c14`
* verdict: **KILLED**

Anchor:
```rust
                if !issuer.status.can_issue() {
                    return Ok(false);
                }
```
Replacement:
```rust
(deleted)
```
Printed by libtest while mutated:
```
test a_suspended_issuer_can_still_revoke_and_update_itself ... FAILED
```

#### J6 can_issue_subcode drops the jurisdiction check

* occurrences checked before applying: **1** (expected 1)
* covering test: `an_issuer_can_grant_itself_any_subcode_and_any_stake_by_updating_itself` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `dd112526c1d4c73c` -> replacement `fa80f260f8a124a0`
* verdict: **KILLED**

Anchor:
```rust
                if !issuer.jurisdictions.is_empty()
                    && !issuer
                        .jurisdictions
                        .iter()
                        .any(|j| j == jurisdiction || j == "*")
                {
                    return Ok(false);
                }
```
Replacement:
```rust
                let _ = jurisdiction;
```
Printed by libtest while mutated:
```
test an_issuer_can_grant_itself_any_subcode_and_any_stake_by_updating_itself ... FAILED
```

#### J7 can_issue_subcode drops the subcode check

* occurrences checked before applying: **1** (expected 1)
* covering test: `an_issuer_can_grant_itself_any_subcode_and_any_stake_by_updating_itself` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `267055858188f09a` -> replacement `e3b0c44298fc1c14`
* verdict: **KILLED**

Anchor:
```rust
                if !issuer.authorized_subcodes.contains(&subcode) {
                    return Ok(false);
                }
```
Replacement:
```rust
(deleted)
```
Printed by libtest while mutated:
```
test an_issuer_can_grant_itself_any_subcode_and_any_stake_by_updating_itself ... FAILED
```

### `crates/state/src/docclass_executor.rs`


#### I1 reactivation drops its suspended-only guard

* occurrences checked before applying: **1** (expected 1)
* covering test: `without_the_suspension_the_same_reactivation_is_refused` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `5e1ebc4ac3f477e3` -> replacement `e3b0c44298fc1c14`
* verdict: **KILLED**

Anchor:
```rust
        let status = Self::v_get_revocation_status(view, &reactivate.credential_id)?;
        if status != RevocationStatus::Suspended {
            return Ok(DocClassExecutionResult::failure("Only suspended can be reactivated"));
        }
```
Replacement:
```rust
(deleted)
```
Printed by libtest while mutated:
```
test without_the_suspension_the_same_reactivation_is_refused ... FAILED
```

#### I2 suspension refuses an already-revoked credential

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_revoked_credential_can_be_suspended_and_then_reactivated` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `bbd0f66e3eb17d14` -> replacement `6fdf1a50a9ae594b`
* verdict: **KILLED**

Anchor:
```rust
        if !Self::check_revoke_auth(view, sender, &suspend.credential_id)? {
            return Ok(DocClassExecutionResult::failure("Not authorized"));
        }
```
Replacement:
```rust
        if !Self::check_revoke_auth(view, sender, &suspend.credential_id)? {
            return Ok(DocClassExecutionResult::failure("Not authorized"));
        }
        if Self::v_get_revocation_status(view, &suspend.credential_id)?
            == RevocationStatus::Revoked
        {
            return Ok(DocClassExecutionResult::failure("Already revoked"));
        }
```
Printed by libtest while mutated:
```
test a_revoked_credential_can_be_suspended_and_then_reactivated ... FAILED
```

#### I3 issuer update keeps the recorded stake

* occurrences checked before applying: **1** (expected 1)
* covering test: `an_issuer_can_grant_itself_any_subcode_and_any_stake_by_updating_itself` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `a766305c422a012e` -> replacement `429bba9fa84676bd`
* verdict: **KILLED**

Anchor:
```rust
        if !Self::v_issuer_is_registered(view, sender)? {
            return Ok(DocClassExecutionResult::failure("Not registered"));
        }

        StateManager::v_deduct(view, sender, fee)?;
```
Replacement:
```rust
        let existing = match Self::v_get_docclass_issuer(view, sender)? {
            Some(i) => i,
            None => return Ok(DocClassExecutionResult::failure("Not registered")),
        };
        let mut updated = updated;
        updated.stake_amount = existing.stake_amount;

        StateManager::v_deduct(view, sender, fee)?;
```
Printed by libtest while mutated:
```
test an_issuer_can_grant_itself_any_subcode_and_any_stake_by_updating_itself ... FAILED
```

#### I4 identity creation forces the status to Active

* occurrences checked before applying: **1** (expected 1)
* covering test: `an_identity_root_is_stored_exactly_as_the_sender_supplied_it` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `1b21c0fc09451937` -> replacement `34c94ba0f18ec35c`
* verdict: **KILLED**

Anchor:
```rust
        if Self::v_identity_root_exists(view, &identity.identity_id)? {
            return Ok(DocClassExecutionResult::failure("Identity already exists"));
        }
```
Replacement:
```rust
        if Self::v_identity_root_exists(view, &identity.identity_id)? {
            return Ok(DocClassExecutionResult::failure("Identity already exists"));
        }
        let mut identity = identity;
        identity.status = IdentityStatus::Active;
```
Printed by libtest while mutated:
```
test an_identity_root_is_stored_exactly_as_the_sender_supplied_it ... FAILED
```

#### I5 credential update writes the row back

* occurrences checked before applying: **1** (expected 1)
* covering test: `update_credential_charges_a_fee_and_writes_nothing` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `3ed4d5673cba4e91` -> replacement `643873fd3eba6873`
* verdict: **KILLED**

Anchor:
```rust
        StateManager::v_deduct(view, sender, fee)?;
        StateManager::v_credit(view, proposer, fee)?;
        StateManager::v_increment_nonce(view, sender)?;

        Ok(DocClassExecutionResult::success(Some(update.credential_id)))
```
Replacement:
```rust
        StateManager::v_deduct(view, sender, fee)?;
        StateManager::v_credit(view, proposer, fee)?;
        StateManager::v_increment_nonce(view, sender)?;

        if let Some(a) = Self::v_get_eligibility(view, &update.credential_id)? {
            Self::v_put_eligibility(view, &a)?;
        }

        Ok(DocClassExecutionResult::success(Some(update.credential_id)))
```
Printed by libtest while mutated:
```
test update_credential_charges_a_fee_and_writes_nothing ... FAILED
```

#### I6 registration pays the stake to the proposer

* occurrences checked before applying: **1** (expected 1)
* covering test: `the_registration_stake_is_deducted_from_the_sender_and_paid_to_nobody` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `c0d5103541a7d369` -> replacement `164789176ba7d162`
* verdict: **KILLED**

Anchor:
```rust
        let total = fee.saturating_add(issuer.stake_amount);
        StateManager::v_deduct(view, sender, total)?;
        StateManager::v_credit(view, proposer, fee)?;
```
Replacement:
```rust
        let total = fee.saturating_add(issuer.stake_amount);
        StateManager::v_deduct(view, sender, total)?;
        StateManager::v_credit(view, proposer, total)?;
```
Printed by libtest while mutated:
```
test the_registration_stake_is_deducted_from_the_sender_and_paid_to_nobody ... FAILED
```

#### I7 revocation consults the issuer registry

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_suspended_issuer_can_still_revoke_and_update_itself` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `6aacf82f53457876` -> replacement `e29fef4d80494a72`
* verdict: **KILLED**

Anchor:
```rust
        if !Self::check_revoke_auth(view, sender, &revoke.credential_id)? {
            return Ok(DocClassExecutionResult::failure("Not authorized"));
        }
```
Replacement:
```rust
        if !Self::check_revoke_auth(view, sender, &revoke.credential_id)? {
            return Ok(DocClassExecutionResult::failure("Not authorized"));
        }
        if !Self::v_can_issue_subcode(
            view,
            sender,
            DocSubcode::EligibilityAttestation,
            "US",
        )? {
            return Ok(DocClassExecutionResult::failure("Issuer not authorized"));
        }
```
Printed by libtest while mutated:
```
test a_suspended_issuer_can_still_revoke_and_update_itself ... FAILED
```

#### I8 issuer deactivation is admin-only

* occurrences checked before applying: **1** (expected 1)
* covering test: `the_registration_stake_is_deducted_from_the_sender_and_paid_to_nobody` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `76498a3262954d2d` -> replacement `50d0837bbbab0e7d`
* verdict: **KILLED**

Anchor:
```rust
        let is_admin = Self::is_docclass_admin(params, sender);
        let is_self = deactivate.issuer_address == *sender;

        if !is_admin && !is_self {
```
Replacement:
```rust
        let is_admin = Self::is_docclass_admin(params, sender);
        let is_self = false;

        if !is_admin && !is_self {
```
Printed by libtest while mutated:
```
test the_registration_stake_is_deducted_from_the_sender_and_paid_to_nobody ... FAILED
```

#### I9 schema validation is active from genesis

* occurrences checked before applying: **1** (expected 1)
* covering test: `schema_validation_is_inactive_below_its_activation_height` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `a766d90fd1f108d7` -> replacement `45c6f4d1a3288c15`
* verdict: **KILLED**

Anchor:
```rust
        let validation_result =
            SchemaValidator::new().validate_academic_credential(&credential, block_height);
```
Replacement:
```rust
        let validation_result = SchemaValidator::with_config(crate::SchemaValidatorConfig {
            activation_height: 0,
            enabled: true,
        })
        .validate_academic_credential(&credential, block_height);
```
Printed by libtest while mutated:
```
test schema_validation_is_inactive_below_its_activation_height ... FAILED
```

#### I10 the credential decode fallthrough reports its first error

* occurrences checked before applying: **1** (expected 1)
* covering test: `issue_credential_picks_its_family_by_trying_to_decode_and_falling_through` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `668dfbf00df94a10` -> replacement `ec7603c17c66a2b4`
* verdict: **KILLED**

Anchor:
```rust
        if let Ok(cred) = bincode::deserialize::<AcademicCredential>(data) {
```
Replacement:
```rust
        let cred = bincode::deserialize::<AcademicCredential>(data)
            .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;
        if true {
```
Printed by libtest while mutated:
```
test issue_credential_picks_its_family_by_trying_to_decode_and_falling_through ... FAILED
```

#### J1 identity creation drops its controller check

* occurrences checked before applying: **1** (expected 1)
* covering test: `registration_and_identity_creation_are_bound_to_the_sender` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `c235545ec301a875` -> replacement `e3b0c44298fc1c14`
* verdict: **KILLED**

Anchor:
```rust
        if identity.controller != *sender {
            return Ok(DocClassExecutionResult::failure("Controller must be sender"));
        }
```
Replacement:
```rust
(deleted)
```
Printed by libtest while mutated:
```
test registration_and_identity_creation_are_bound_to_the_sender ... FAILED
```

#### J2 revocation authorization always passes

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_third_party_cannot_revoke_someone_elses_credential` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `8e7a7588c8f805ff` -> replacement `2cf0013817b07fdf`
* verdict: **KILLED**

Anchor:
```rust
        if let Some(a) = Self::v_get_eligibility(view, credential_id)? {
            return Ok(a.issuer == *sender);
        }
```
Replacement:
```rust
        if let Some(a) = Self::v_get_eligibility(view, credential_id)? {
            let _ = a;
            return Ok(true);
        }
```
Printed by libtest while mutated:
```
test a_third_party_cannot_revoke_someone_elses_credential ... FAILED
```

#### J8 issuer registration drops its address check

* occurrences checked before applying: **1** (expected 1)
* covering test: `registration_and_identity_creation_are_bound_to_the_sender` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `56102f2e9be60d47` -> replacement `e3b0c44298fc1c14`
* verdict: **KILLED**

Anchor:
```rust
        if issuer.address != *sender {
            return Ok(DocClassExecutionResult::failure("Address must be sender"));
        }
```
Replacement:
```rust
(deleted)
```
Printed by libtest while mutated:
```
test registration_and_identity_creation_are_bound_to_the_sender ... FAILED
```

### `crates/storage/src/docclass_store.rs`


#### E1 identity-root key is truncated

* occurrences checked before applying: **1** (expected 1)
* covering test: `an_identity_row_is_bincode_at_the_identity_id_key_and_indexes_its_subject` (`sumchain-storage --test docclass_codec_parity`)
* anchor sha256[:16] `78590fbace9615af` -> replacement `92de38b7fd7778ae`
* verdict: **KILLED**

Anchor:
```rust
pub fn identity_root_key(identity_id: &CredentialId) -> &[u8] {
    identity_id
}
```
Replacement:
```rust
pub fn identity_root_key(identity_id: &CredentialId) -> &[u8] {
    &identity_id[..16]
}
```
Printed by libtest while mutated:
```
test an_identity_row_is_bincode_at_the_identity_id_key_and_indexes_its_subject ... FAILED
```

#### E2 eligibility key is truncated

* occurrences checked before applying: **1** (expected 1)
* covering test: `an_eligibility_row_is_bincode_and_indexes_both_its_subject_and_its_issuer` (`sumchain-storage --test docclass_codec_parity`)
* anchor sha256[:16] `fa87302634cf2672` -> replacement `c988bcc3836a9d51`
* verdict: **KILLED**

Anchor:
```rust
pub fn eligibility_key(credential_id: &CredentialId) -> &[u8] {
    credential_id
}
```
Replacement:
```rust
pub fn eligibility_key(credential_id: &CredentialId) -> &[u8] {
    &credential_id[..16]
}
```
Printed by libtest while mutated:
```
test an_eligibility_row_is_bincode_and_indexes_both_its_subject_and_its_issuer ... FAILED
```

#### E3 credential key is truncated

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_credential_row_is_bincode_and_indexes_both_its_subject_and_its_issuer` (`sumchain-storage --test docclass_codec_parity`)
* anchor sha256[:16] `12dc0851aa724014` -> replacement `bef8565eeda8b538`
* verdict: **KILLED**

Anchor:
```rust
pub fn credential_key(credential_id: &CredentialId) -> &[u8] {
    credential_id
}
```
Replacement:
```rust
pub fn credential_key(credential_id: &CredentialId) -> &[u8] {
    &credential_id[..16]
}
```
Printed by libtest while mutated:
```
test a_credential_row_is_bincode_and_indexes_both_its_subject_and_its_issuer ... FAILED
```

#### E4 issuer key is truncated

* occurrences checked before applying: **1** (expected 1)
* covering test: `an_issuer_row_is_bincode_at_the_raw_address_bytes_and_writes_no_index` (`sumchain-storage --test docclass_codec_parity`)
* anchor sha256[:16] `45f17670bad2cdd9` -> replacement `e15f82cb76007d49`
* verdict: **KILLED**

Anchor:
```rust
pub fn docclass_issuer_key(address: &Address) -> &[u8] {
    address.as_bytes()
}
```
Replacement:
```rust
pub fn docclass_issuer_key(address: &Address) -> &[u8] {
    &address.as_bytes()[..10]
}
```
Printed by libtest while mutated:
```
test an_issuer_row_is_bincode_at_the_raw_address_bytes_and_writes_no_index ... FAILED
```

#### E5 subject index key is truncated

* occurrences checked before applying: **1** (expected 1)
* covering test: `an_identity_row_is_bincode_at_the_identity_id_key_and_indexes_its_subject` (`sumchain-storage --test docclass_codec_parity`)
* anchor sha256[:16] `1194cf805dc815ab` -> replacement `46de8921903d4af2`
* verdict: **KILLED**

Anchor:
```rust
pub fn subject_index_key(subject_commitment: &SubjectCommitment) -> &[u8] {
    subject_commitment
}
```
Replacement:
```rust
pub fn subject_index_key(subject_commitment: &SubjectCommitment) -> &[u8] {
    &subject_commitment[..16]
}
```
Printed by libtest while mutated:
```
test an_identity_row_is_bincode_at_the_identity_id_key_and_indexes_its_subject ... FAILED
```

#### E6 issuer index key is truncated

* occurrences checked before applying: **1** (expected 1)
* covering test: `an_eligibility_row_is_bincode_and_indexes_both_its_subject_and_its_issuer` (`sumchain-storage --test docclass_codec_parity`)
* anchor sha256[:16] `157579899cfcb388` -> replacement `15e73bc34a3a01b0`
* verdict: **KILLED**

Anchor:
```rust
pub fn issuer_index_key(issuer: &Address) -> &[u8] {
    issuer.as_bytes()
}
```
Replacement:
```rust
pub fn issuer_index_key(issuer: &Address) -> &[u8] {
    &issuer.as_bytes()[..10]
}
```
Printed by libtest while mutated:
```
test an_eligibility_row_is_bincode_and_indexes_both_its_subject_and_its_issuer ... FAILED
```

#### E7 revocation key height is little-endian

* occurrences checked before applying: **1** (expected 1)
* covering test: `the_two_composite_keys_are_big_endian` (`sumchain-storage --test docclass_codec_parity`)
* anchor sha256[:16] `8bcf10653465c746` -> replacement `948ddaa4e5a1d33c`
* verdict: **KILLED**

Anchor:
```rust
    key.extend_from_slice(credential_id);
    key.extend_from_slice(&revoked_at_height.to_be_bytes());
```
Replacement:
```rust
    key.extend_from_slice(credential_id);
    key.extend_from_slice(&revoked_at_height.to_le_bytes());
```
Printed by libtest while mutated:
```
test the_two_composite_keys_are_big_endian ... FAILED
```

#### E8 revocation key puts the height first

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_revocation_row_is_bincode_at_the_credential_id_and_height_key` (`sumchain-storage --test docclass_codec_parity`)
* anchor sha256[:16] `fa90782a3ee4ee16` -> replacement `3d81aef8696a2604`
* verdict: **KILLED**

Anchor:
```rust
    let mut key = Vec::with_capacity(40);
    key.extend_from_slice(credential_id);
    key.extend_from_slice(&revoked_at_height.to_be_bytes());
    key
```
Replacement:
```rust
    let mut key = Vec::with_capacity(40);
    key.extend_from_slice(&revoked_at_height.to_be_bytes());
    key.extend_from_slice(credential_id);
    key
```
Printed by libtest while mutated:
```
test a_revocation_row_is_bincode_at_the_credential_id_and_height_key ... FAILED
```

#### E9 event key height is little-endian

* occurrences checked before applying: **1** (expected 1)
* covering test: `the_two_composite_keys_are_big_endian` (`sumchain-storage --test docclass_codec_parity`)
* anchor sha256[:16] `65c2aa06a61301c7` -> replacement `c537cf866cd947c3`
* verdict: **KILLED**

Anchor:
```rust
    key.extend_from_slice(&block_height.to_be_bytes());
    key.extend_from_slice(&tx_index.to_be_bytes());
```
Replacement:
```rust
    key.extend_from_slice(&block_height.to_le_bytes());
    key.extend_from_slice(&tx_index.to_be_bytes());
```
Printed by libtest while mutated:
```
test the_two_composite_keys_are_big_endian ... FAILED
```

#### E10 event key drops the event index

* occurrences checked before applying: **1** (expected 1)
* covering test: `an_event_row_is_bincode_at_the_height_txindex_eventindex_key` (`sumchain-storage --test docclass_codec_parity`)
* anchor sha256[:16] `048dd54bac31ad34` -> replacement `739c2e8146b6f7e0`
* verdict: **KILLED**

Anchor:
```rust
    key.extend_from_slice(&event_index.to_be_bytes());
    key
```
Replacement:
```rust
    let _ = event_index;
    key
```
Printed by libtest while mutated:
```
test an_event_row_is_bincode_at_the_height_txindex_eventindex_key ... FAILED
```

#### F1 encode_identity_root changes the row's byte layout

* occurrences checked before applying: **1** (expected 1)
* covering test: `an_identity_row_is_bincode_at_the_identity_id_key_and_indexes_its_subject` (`sumchain-storage --test docclass_codec_parity`)
* anchor sha256[:16] `d293061a5468009b` -> replacement `181cd8d8ffa828dd`
* verdict: **KILLED**

Anchor:
```rust
pub fn encode_identity_root(identity: &IdentityRoot) -> Result<Vec<u8>> {
    bincode::serialize(identity).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Replacement:
```rust
pub fn encode_identity_root(identity: &IdentityRoot) -> Result<Vec<u8>> {
    bincode::serialize(identity)
        .map(|mut v| {
            v.push(0);
            v
        })
        .map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Printed by libtest while mutated:
```
test an_identity_row_is_bincode_at_the_identity_id_key_and_indexes_its_subject ... FAILED
```

#### F2 encode_subject_identity_index changes the row's byte layout

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_second_identity_for_one_subject_appends_to_the_same_pair_list` (`sumchain-storage --test docclass_codec_parity`)
* anchor sha256[:16] `f4a512ef3b246c4d` -> replacement `c5b63e862bbc41d7`
* verdict: **KILLED**

Anchor:
```rust
pub fn encode_subject_identity_index(index: &[(CredentialId, DocSubcode)]) -> Result<Vec<u8>> {
    bincode::serialize(index).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Replacement:
```rust
pub fn encode_subject_identity_index(index: &[(CredentialId, DocSubcode)]) -> Result<Vec<u8>> {
    bincode::serialize(index)
        .map(|mut v| {
            v.push(0);
            v
        })
        .map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Printed by libtest while mutated:
```
test a_second_identity_for_one_subject_appends_to_the_same_pair_list ... FAILED
```

#### F3 encode_eligibility changes the row's byte layout

* occurrences checked before applying: **1** (expected 1)
* covering test: `an_eligibility_row_is_bincode_and_indexes_both_its_subject_and_its_issuer` (`sumchain-storage --test docclass_codec_parity`)
* anchor sha256[:16] `7d2736d60f8abf26` -> replacement `7e55b118ed293cdc`
* verdict: **KILLED**

Anchor:
```rust
pub fn encode_eligibility(attestation: &EligibilityAttestation) -> Result<Vec<u8>> {
    bincode::serialize(attestation).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Replacement:
```rust
pub fn encode_eligibility(attestation: &EligibilityAttestation) -> Result<Vec<u8>> {
    bincode::serialize(attestation)
        .map(|mut v| {
            v.push(0);
            v
        })
        .map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Printed by libtest while mutated:
```
test an_eligibility_row_is_bincode_and_indexes_both_its_subject_and_its_issuer ... FAILED
```

#### F4 encode_credential changes the row's byte layout

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_credential_row_is_bincode_and_indexes_both_its_subject_and_its_issuer` (`sumchain-storage --test docclass_codec_parity`)
* anchor sha256[:16] `f0351de6c0ce1683` -> replacement `0c0cf92111313aca`
* verdict: **KILLED**

Anchor:
```rust
pub fn encode_credential(credential: &AcademicCredential) -> Result<Vec<u8>> {
    bincode::serialize(credential).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Replacement:
```rust
pub fn encode_credential(credential: &AcademicCredential) -> Result<Vec<u8>> {
    bincode::serialize(credential)
        .map(|mut v| {
            v.push(0);
            v
        })
        .map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Printed by libtest while mutated:
```
test a_credential_row_is_bincode_and_indexes_both_its_subject_and_its_issuer ... FAILED
```

#### F5 encode_subject_credential_index changes the row's byte layout

* occurrences checked before applying: **1** (expected 1)
* covering test: `an_eligibility_row_is_bincode_and_indexes_both_its_subject_and_its_issuer` (`sumchain-storage --test docclass_codec_parity`)
* anchor sha256[:16] `56fd84e37ba3a1fb` -> replacement `98dadf4785873ab6`
* verdict: **KILLED**

Anchor:
```rust
pub fn encode_subject_credential_index(ids: &[CredentialId]) -> Result<Vec<u8>> {
    bincode::serialize(ids).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Replacement:
```rust
pub fn encode_subject_credential_index(ids: &[CredentialId]) -> Result<Vec<u8>> {
    bincode::serialize(ids)
        .map(|mut v| {
            v.push(0);
            v
        })
        .map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Printed by libtest while mutated:
```
test an_eligibility_row_is_bincode_and_indexes_both_its_subject_and_its_issuer ... FAILED
```

#### F6 encode_issuer_credential_index changes the row's byte layout

* occurrences checked before applying: **1** (expected 1)
* covering test: `two_credentials_from_one_issuer_append_to_the_same_issuer_list` (`sumchain-storage --test docclass_codec_parity`)
* anchor sha256[:16] `346e7a15d9db5344` -> replacement `7f848026070f4c1e`
* verdict: **KILLED**

Anchor:
```rust
pub fn encode_issuer_credential_index(ids: &[CredentialId]) -> Result<Vec<u8>> {
    bincode::serialize(ids).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Replacement:
```rust
pub fn encode_issuer_credential_index(ids: &[CredentialId]) -> Result<Vec<u8>> {
    bincode::serialize(ids)
        .map(|mut v| {
            v.push(0);
            v
        })
        .map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Printed by libtest while mutated:
```
test two_credentials_from_one_issuer_append_to_the_same_issuer_list ... FAILED
```

#### F7 encode_revocation_record changes the row's byte layout

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_revocation_row_is_bincode_at_the_credential_id_and_height_key` (`sumchain-storage --test docclass_codec_parity`)
* anchor sha256[:16] `9a700bb18305851e` -> replacement `86c4305bb56fdb06`
* verdict: **KILLED**

Anchor:
```rust
pub fn encode_revocation_record(record: &RevocationRecord) -> Result<Vec<u8>> {
    bincode::serialize(record).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Replacement:
```rust
pub fn encode_revocation_record(record: &RevocationRecord) -> Result<Vec<u8>> {
    bincode::serialize(record)
        .map(|mut v| {
            v.push(0);
            v
        })
        .map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Printed by libtest while mutated:
```
test a_revocation_row_is_bincode_at_the_credential_id_and_height_key ... FAILED
```

#### F8 encode_docclass_issuer changes the row's byte layout

* occurrences checked before applying: **1** (expected 1)
* covering test: `an_issuer_row_is_bincode_at_the_raw_address_bytes_and_writes_no_index` (`sumchain-storage --test docclass_codec_parity`)
* anchor sha256[:16] `f9a692f9cc02daa6` -> replacement `337db0a47a00afc2`
* verdict: **KILLED**

Anchor:
```rust
pub fn encode_docclass_issuer(issuer: &DocClassIssuer) -> Result<Vec<u8>> {
    bincode::serialize(issuer).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Replacement:
```rust
pub fn encode_docclass_issuer(issuer: &DocClassIssuer) -> Result<Vec<u8>> {
    bincode::serialize(issuer)
        .map(|mut v| {
            v.push(0);
            v
        })
        .map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Printed by libtest while mutated:
```
test an_issuer_row_is_bincode_at_the_raw_address_bytes_and_writes_no_index ... FAILED
```

#### F9 encode_docclass_event changes the row's byte layout

* occurrences checked before applying: **1** (expected 1)
* covering test: `an_event_row_is_bincode_at_the_height_txindex_eventindex_key` (`sumchain-storage --test docclass_codec_parity`)
* anchor sha256[:16] `c0de1cb672508d8b` -> replacement `8bd4671cd6a8956e`
* verdict: **KILLED**

Anchor:
```rust
pub fn encode_docclass_event(event: &DocClassEvent) -> Result<Vec<u8>> {
    bincode::serialize(event).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Replacement:
```rust
pub fn encode_docclass_event(event: &DocClassEvent) -> Result<Vec<u8>> {
    bincode::serialize(event)
        .map(|mut v| {
            v.push(0);
            v
        })
        .map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Printed by libtest while mutated:
```
test an_event_row_is_bincode_at_the_height_txindex_eventindex_key ... FAILED
```

#### F10 decode_subject_identity_index turns a decode failure into an empty list

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_malformed_row_is_an_error_from_every_decoding_reader` (`sumchain-storage --test docclass_codec_parity`)
* anchor sha256[:16] `d7f6bbeffb5bf564` -> replacement `aeeb6f8b1112bf3c`
* verdict: **KILLED**

Anchor:
```rust
pub fn decode_subject_identity_index(bytes: &[u8]) -> Result<Vec<(CredentialId, DocSubcode)>> {
    bincode::deserialize(bytes).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Replacement:
```rust
pub fn decode_subject_identity_index(bytes: &[u8]) -> Result<Vec<(CredentialId, DocSubcode)>> {
    Ok(bincode::deserialize(bytes).unwrap_or_default())
}
```
Printed by libtest while mutated:
```
test a_malformed_row_is_an_error_from_every_decoding_reader ... FAILED
```

#### F11 decode_subject_credential_index turns a decode failure into an empty list

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_malformed_row_is_an_error_from_every_decoding_reader` (`sumchain-storage --test docclass_codec_parity`)
* anchor sha256[:16] `3a190155d5309f09` -> replacement `6f275ba04852e612`
* verdict: **KILLED**

Anchor:
```rust
pub fn decode_subject_credential_index(bytes: &[u8]) -> Result<Vec<CredentialId>> {
    bincode::deserialize(bytes).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Replacement:
```rust
pub fn decode_subject_credential_index(bytes: &[u8]) -> Result<Vec<CredentialId>> {
    Ok(bincode::deserialize(bytes).unwrap_or_default())
}
```
Printed by libtest while mutated:
```
test a_malformed_row_is_an_error_from_every_decoding_reader ... FAILED
```

#### F12 decode_issuer_credential_index turns a decode failure into an empty list

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_malformed_row_is_an_error_from_every_decoding_reader` (`sumchain-storage --test docclass_codec_parity`)
* anchor sha256[:16] `3f1c794f8dbda038` -> replacement `fbc25627d51a7051`
* verdict: **KILLED**

Anchor:
```rust
pub fn decode_issuer_credential_index(bytes: &[u8]) -> Result<Vec<CredentialId>> {
    bincode::deserialize(bytes).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Replacement:
```rust
pub fn decode_issuer_credential_index(bytes: &[u8]) -> Result<Vec<CredentialId>> {
    Ok(bincode::deserialize(bytes).unwrap_or_default())
}
```
Printed by libtest while mutated:
```
test a_malformed_row_is_an_error_from_every_decoding_reader ... FAILED
```

### `crates/state/src/executor.rs`


#### H1 the live arm forwards the real block timestamp

* occurrences checked before applying: **1** (expected 1)
* covering test: `the_block_timestamp_reaching_docclass_operations_is_always_zero` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `d7c7f35cece8ea76` -> replacement `7d66b1018d18d191`
* verdict: **KILLED**

Anchor:
```rust
                        let result = DocClassExecutor::execute(
                            view,
                            &self.params,
                            &v2_tx.from,
                            &docclass_data,
                            proposer,
                            v2_tx.fee,
                            block_height,
                            0, // block_timestamp placeholder
```
Replacement:
```rust
                        let result = DocClassExecutor::execute(
                            view,
                            &self.params,
                            &v2_tx.from,
                            &docclass_data,
                            proposer,
                            v2_tx.fee,
                            block_height,
                            block_timestamp,
```
Printed by libtest while mutated:
```
test the_block_timestamp_reaching_docclass_operations_is_always_zero ... FAILED
```

#### H2 the live arm substitutes default chain params

* occurrences checked before applying: **1** (expected 1)
* covering test: `an_issuer_registered_earlier_in_the_block_can_issue_a_credential` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `d7c7f35cece8ea76` -> replacement `f2daa9e63c59fe09`
* verdict: **KILLED**

Anchor:
```rust
                        let result = DocClassExecutor::execute(
                            view,
                            &self.params,
                            &v2_tx.from,
                            &docclass_data,
                            proposer,
                            v2_tx.fee,
                            block_height,
                            0, // block_timestamp placeholder
```
Replacement:
```rust
                        let result = DocClassExecutor::execute(
                            view,
                            &ChainParams::default(),
                            &v2_tx.from,
                            &docclass_data,
                            proposer,
                            v2_tx.fee,
                            block_height,
                            0, // block_timestamp placeholder
```
Printed by libtest while mutated:
```
test an_issuer_registered_earlier_in_the_block_can_issue_a_credential ... FAILED
```

#### H3 the v2 arm forwards the real block timestamp

* occurrences checked before applying: **1** (expected 1)
* covering test: `the_v2_dispatch_surface_also_stages_docclass_rows` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `be2046eb9861fdea` -> replacement `b3f19ab221aa9e0f`
* verdict: **KILLED**

Anchor:
```rust
                let result = DocClassExecutor::execute(
                    view,
                    &self.params,
                    &tx.from,
                    docclass_data,
                    proposer,
                    tx.fee,
                    block_height,
                    0, // block_timestamp placeholder
```
Replacement:
```rust
                let result = DocClassExecutor::execute(
                    view,
                    &self.params,
                    &tx.from,
                    docclass_data,
                    proposer,
                    tx.fee,
                    block_height,
                    block_timestamp,
```
Printed by libtest while mutated:
```
test the_v2_dispatch_surface_also_stages_docclass_rows ... FAILED
```

#### H4 the v2 arm substitutes default chain params

* occurrences checked before applying: **1** (expected 1)
* covering test: `the_v2_dispatch_surface_also_stages_docclass_rows` (`sumchain-state --test docclass_routing`)
* anchor sha256[:16] `be2046eb9861fdea` -> replacement `e2895ab7d6eef288`
* verdict: **KILLED**

Anchor:
```rust
                let result = DocClassExecutor::execute(
                    view,
                    &self.params,
                    &tx.from,
                    docclass_data,
                    proposer,
                    tx.fee,
                    block_height,
                    0, // block_timestamp placeholder
```
Replacement:
```rust
                let result = DocClassExecutor::execute(
                    view,
                    &ChainParams::default(),
                    &tx.from,
                    docclass_data,
                    proposer,
                    tx.fee,
                    block_height,
                    0, // block_timestamp placeholder
```
Printed by libtest while mutated:
```
test the_v2_dispatch_surface_also_stages_docclass_rows ... FAILED
```

## Totals and post-run hashes

```
=== totals ===
  killed: 88
  declared: 88   scored: 88

=== post-run hashes (authoritative) ===
  MATCH   5925bf4e0ab72b758cd6667dddcf928e80366485f60f49e014fb9ad7ef0bd514  crates/state/src/docclass_view.rs
  MATCH   a153540882e95497a56046b09d968dae5a30061ea414dc59b49cf1a6b2a9a3ef  crates/state/src/docclass_executor.rs
  MATCH   2f2955959f43c6a5aa554a6dece59752116fed8aa9cfe1503ec86ea17fb02335  crates/state/src/executor.rs
  MATCH   d2f2828d06848257b7eb16bebb7e14d30a2a1c9cb40466dd16db2e04341779eb  crates/storage/src/docclass_store.rs
  all four byte-identical to pre-run: True

=== anchors resolve exactly once again ===
  88/88
```


## Residue

```
=== 1. the four mutated files vs the pre-run backups ===
  MATCH  crates/state/src/docclass_view.rs  5925bf4e0ab72b75
  MATCH  crates/state/src/docclass_executor.rs  a153540882e95497
  MATCH  crates/state/src/executor.rs  2f2955959f43c6a5
  MATCH  crates/storage/src/docclass_store.rs  d2f2828d06848257
  all four restored: True

=== 2. whole-crates scan, 64 specific replacements ===
  residue: NONE

  24 replacements are text that already occurs in the pristine
  tree and are covered by check 1 only -- a text scan for them is meaningless.

=== 3. every anchor still resolves exactly once ===
  anchors resolving once: 88/88; not-once: []
```
