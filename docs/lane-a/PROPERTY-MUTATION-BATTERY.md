# Property routing: mutation battery

NOT DEPLOYABLE ON ITS OWN, like the rest of this lane.


Each mutation is applied to the tree that this commit contains, one at a time,
and the NAMED covering test is run BY NAME (`-- --exact <test>`). A kill
requires that test to appear in libtest's output AND to have failed, so
"survived" means the named test passed with the mutation in place rather than
that some other test happened to fail. A mutation whose anchor does not resolve
exactly once aborts the whole run before anything is applied; one that does not
compile, and one whose covering test does not appear, are separate categories
that never count as kills. Restoration happens in a `finally` and on
SIGINT/SIGTERM, and every restore is checked against the pre-run hash.

Whole-tree text scanning for leftover replacements is diagnostic only. A
replacement is usable as a residue marker only if it does not already occur in
the pristine tree; 31 of these do occur there -- strings such as `Ok(false)`,
`Ok(())`, `.map_err(StateError::Storage)` and outright deletions -- so finding
them proves nothing. The final evidence is 119 mutations total,
88 scanned specifically by text, and 31 covered by exact file hashes
alone. The authoritative residue check for all 119 is the pre/post hash of every
mutated file, printed at the end of this document.


## Pre-run file hashes

```
  aa088d5e1911a51bae0bc2a4df98adb7f32950d335c110ab0003512c4972f68c  crates/state/src/property_view.rs
  117e19a10ac32dcdad83724eaed988027e9b9378af6c2ce29328ef9c775e8df0  crates/state/src/property_executor.rs
  240c965975421c3aa8f6905014a18dade71fa3ceb00bf0c628c9044625fb3cf4  crates/state/src/executor.rs
  82c25d7c033798fa3a5987ffae1fbd5276d00d2a8aaf7adaa64942d872e86f52  crates/storage/src/property_store.rs
```


## The 119 mutations


### `crates/state/src/property_view.rs`


#### A1 asset read sees nothing

* occurrences checked before applying: **1** (expected 1)
* covering test: `every_dependent_row_finds_its_parent_within_one_block` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `3023436c80230931` -> replacement `c832b86ec08ac5f2`
* verdict: **KILLED**

Anchor:
```rust
        match view
            .get(cf::PROPERTY_ASSETS, asset_key(asset_id))
            .map_err(StateError::Storage)?
        {
```
Replacement:
```rust
        match None::<Vec<u8>> {
```
Printed by libtest while mutated:
```
test every_dependent_row_finds_its_parent_within_one_block ... FAILED
```

#### A2 title-event read sees nothing

* occurrences checked before applying: **1** (expected 1)
* covering test: `every_remaining_status_transition_reads_the_row_the_one_before_it_staged` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `24b0042381a742ac` -> replacement `c832b86ec08ac5f2`
* verdict: **KILLED**

Anchor:
```rust
        match view
            .get(cf::PROPERTY_TITLE_EVENTS, title_event_key(event_id))
            .map_err(StateError::Storage)?
        {
```
Replacement:
```rust
        match None::<Vec<u8>> {
```
Printed by libtest while mutated:
```
test every_remaining_status_transition_reads_the_row_the_one_before_it_staged ... FAILED
```

#### A3 encumbrance read sees nothing

* occurrences checked before applying: **1** (expected 1)
* covering test: `every_remaining_status_transition_reads_the_row_the_one_before_it_staged` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `eb37403f34dc4717` -> replacement `c832b86ec08ac5f2`
* verdict: **KILLED**

Anchor:
```rust
        match view
            .get(cf::PROPERTY_ENCUMBRANCES, encumbrance_key(encumbrance_id))
            .map_err(StateError::Storage)?
        {
```
Replacement:
```rust
        match None::<Vec<u8>> {
```
Printed by libtest while mutated:
```
test every_remaining_status_transition_reads_the_row_the_one_before_it_staged ... FAILED
```

#### A4 coverage read sees nothing

* occurrences checked before applying: **1** (expected 1)
* covering test: `suspend_then_reinstate_in_one_block_reactivates_the_coverage` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `c027cb9c1b5c94f5` -> replacement `c832b86ec08ac5f2`
* verdict: **KILLED**

Anchor:
```rust
        match view
            .get(cf::PROPERTY_COVERAGE, coverage_key(coverage_id))
            .map_err(StateError::Storage)?
        {
```
Replacement:
```rust
        match None::<Vec<u8>> {
```
Printed by libtest while mutated:
```
test suspend_then_reinstate_in_one_block_reactivates_the_coverage ... FAILED
```

#### A5 claim read sees nothing

* occurrences checked before applying: **1** (expected 1)
* covering test: `approve_then_pay_in_one_block_records_both_commitments` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `96fa19c6f86c46cc` -> replacement `c832b86ec08ac5f2`
* verdict: **KILLED**

Anchor:
```rust
        match view
            .get(cf::PROPERTY_CLAIMS, claim_key(claim_id))
            .map_err(StateError::Storage)?
        {
```
Replacement:
```rust
        match None::<Vec<u8>> {
```
Printed by libtest while mutated:
```
test approve_then_pay_in_one_block_records_both_commitments ... FAILED
```

#### A6 jurisdiction index read sees nothing

* occurrences checked before applying: **1** (expected 1)
* covering test: `all_five_indexes_accumulate_within_one_block` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `f4546752a9102900` -> replacement `c832b86ec08ac5f2`
* verdict: **KILLED**

Anchor:
```rust
        match view
            .get(
                cf::PROPERTY_JURISDICTION_INDEX,
                jurisdiction_index_key(jurisdiction),
            )
            .map_err(StateError::Storage)?
        {
```
Replacement:
```rust
        match None::<Vec<u8>> {
```
Printed by libtest while mutated:
```
test all_five_indexes_accumulate_within_one_block ... FAILED
```

#### A7 asset-title index read sees nothing

* occurrences checked before applying: **1** (expected 1)
* covering test: `all_five_indexes_accumulate_within_one_block` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `c38de7d2c4e2236b` -> replacement `c832b86ec08ac5f2`
* verdict: **KILLED**

Anchor:
```rust
        match view
            .get(
                cf::PROPERTY_ASSET_TITLE_INDEX,
                asset_title_index_key(asset_id),
            )
            .map_err(StateError::Storage)?
        {
```
Replacement:
```rust
        match None::<Vec<u8>> {
```
Printed by libtest while mutated:
```
test all_five_indexes_accumulate_within_one_block ... FAILED
```

#### A8 asset-encumbrance index read sees nothing

* occurrences checked before applying: **1** (expected 1)
* covering test: `all_five_indexes_accumulate_within_one_block` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `2f55aa7ef6e206d3` -> replacement `c832b86ec08ac5f2`
* verdict: **KILLED**

Anchor:
```rust
        match view
            .get(
                cf::PROPERTY_ASSET_ENCUMBRANCE_INDEX,
                asset_encumbrance_index_key(asset_id),
            )
            .map_err(StateError::Storage)?
        {
```
Replacement:
```rust
        match None::<Vec<u8>> {
```
Printed by libtest while mutated:
```
test all_five_indexes_accumulate_within_one_block ... FAILED
```

#### A9 asset-coverage index read sees nothing

* occurrences checked before applying: **1** (expected 1)
* covering test: `all_five_indexes_accumulate_within_one_block` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `33156704a781e072` -> replacement `c832b86ec08ac5f2`
* verdict: **KILLED**

Anchor:
```rust
        match view
            .get(
                cf::PROPERTY_ASSET_COVERAGE_INDEX,
                asset_coverage_index_key(asset_id),
            )
            .map_err(StateError::Storage)?
        {
```
Replacement:
```rust
        match None::<Vec<u8>> {
```
Printed by libtest while mutated:
```
test all_five_indexes_accumulate_within_one_block ... FAILED
```

#### A10 coverage-claim index read sees nothing

* occurrences checked before applying: **1** (expected 1)
* covering test: `all_five_indexes_accumulate_within_one_block` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `acc23d729fd9dace` -> replacement `c832b86ec08ac5f2`
* verdict: **KILLED**

Anchor:
```rust
        match view
            .get(
                cf::PROPERTY_COVERAGE_CLAIM_INDEX,
                coverage_claim_index_key(coverage_id),
            )
            .map_err(StateError::Storage)?
        {
```
Replacement:
```rust
        match None::<Vec<u8>> {
```
Printed by libtest while mutated:
```
test all_five_indexes_accumulate_within_one_block ... FAILED
```

#### B1 asset exists always false

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_duplicate_id_in_the_same_block_is_refused_for_every_guarded_family` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `2bfe4a7c937f2666` -> replacement `e3b3651260f4ca5a`
* verdict: **KILLED**

Anchor:
```rust
        view.contains(cf::PROPERTY_ASSETS, asset_key(asset_id))
            .map_err(StateError::Storage)
```
Replacement:
```rust
        Ok(false)
```
Printed by libtest while mutated:
```
test a_duplicate_id_in_the_same_block_is_refused_for_every_guarded_family ... FAILED
```

#### B2 title-event exists always false

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_duplicate_id_in_the_same_block_is_refused_for_every_guarded_family` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `f63f9eace5a625d8` -> replacement `e3b3651260f4ca5a`
* verdict: **KILLED**

Anchor:
```rust
        view.contains(cf::PROPERTY_TITLE_EVENTS, title_event_key(event_id))
            .map_err(StateError::Storage)
```
Replacement:
```rust
        Ok(false)
```
Printed by libtest while mutated:
```
test a_duplicate_id_in_the_same_block_is_refused_for_every_guarded_family ... FAILED
```

#### B3 encumbrance exists always false

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_duplicate_id_in_the_same_block_is_refused_for_every_guarded_family` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `0f1653cb76364cd4` -> replacement `e3b3651260f4ca5a`
* verdict: **KILLED**

Anchor:
```rust
        view.contains(cf::PROPERTY_ENCUMBRANCES, encumbrance_key(encumbrance_id))
            .map_err(StateError::Storage)
```
Replacement:
```rust
        Ok(false)
```
Printed by libtest while mutated:
```
test a_duplicate_id_in_the_same_block_is_refused_for_every_guarded_family ... FAILED
```

#### B4 coverage exists always false

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_duplicate_id_in_the_same_block_is_refused_for_every_guarded_family` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `997a33a527e793af` -> replacement `e3b3651260f4ca5a`
* verdict: **KILLED**

Anchor:
```rust
        view.contains(cf::PROPERTY_COVERAGE, coverage_key(coverage_id))
            .map_err(StateError::Storage)
```
Replacement:
```rust
        Ok(false)
```
Printed by libtest while mutated:
```
test a_duplicate_id_in_the_same_block_is_refused_for_every_guarded_family ... FAILED
```

#### B5 claim exists always false

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_duplicate_id_in_the_same_block_is_refused_for_every_guarded_family` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `4a66993e0b900ca0` -> replacement `e3b3651260f4ca5a`
* verdict: **KILLED**

Anchor:
```rust
        view.contains(cf::PROPERTY_CLAIMS, claim_key(claim_id))
            .map_err(StateError::Storage)
```
Replacement:
```rust
        Ok(false)
```
Printed by libtest while mutated:
```
test a_duplicate_id_in_the_same_block_is_refused_for_every_guarded_family ... FAILED
```

#### B6 proof exists always false

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_corrupt_proof_row_is_read_as_presence_not_as_corruption` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `ac53ccf8a5d24ae2` -> replacement `e3b3651260f4ca5a`
* verdict: **KILLED**

Anchor:
```rust
        view.contains(cf::PROPERTY_PROOFS, property_proof_key(proof_id))
            .map_err(StateError::Storage)
```
Replacement:
```rust
        Ok(false)
```
Printed by libtest while mutated:
```
test a_corrupt_proof_row_is_read_as_presence_not_as_corruption ... FAILED
```

#### C1 asset row not written

* occurrences checked before applying: **1** (expected 1)
* covering test: `every_dependent_row_finds_its_parent_within_one_block` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `edea296eecf4686a` -> replacement `e3b0c44298fc1c14`
* verdict: **KILLED**

Anchor:
```rust
        view.put(cf::PROPERTY_ASSETS, asset_key(&asset.asset_id), &bytes)
            .map_err(StateError::Storage)?;
```
Replacement:
```rust
(deleted)
```
Printed by libtest while mutated:
```
test every_dependent_row_finds_its_parent_within_one_block ... FAILED
```

#### C2 title-event row not written

* occurrences checked before applying: **1** (expected 1)
* covering test: `every_dependent_row_finds_its_parent_within_one_block` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `814f31a3284c2451` -> replacement `e3b0c44298fc1c14`
* verdict: **KILLED**

Anchor:
```rust
        view.put(
            cf::PROPERTY_TITLE_EVENTS,
            title_event_key(&event.event_id),
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
test every_dependent_row_finds_its_parent_within_one_block ... FAILED
```

#### C3 encumbrance row not written

* occurrences checked before applying: **1** (expected 1)
* covering test: `every_dependent_row_finds_its_parent_within_one_block` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `53079d61207593ca` -> replacement `e3b0c44298fc1c14`
* verdict: **KILLED**

Anchor:
```rust
        view.put(
            cf::PROPERTY_ENCUMBRANCES,
            encumbrance_key(&encumbrance.encumbrance_id),
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
test every_dependent_row_finds_its_parent_within_one_block ... FAILED
```

#### C4 coverage row not written

* occurrences checked before applying: **1** (expected 1)
* covering test: `every_dependent_row_finds_its_parent_within_one_block` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `24bf589ba4fe8ce8` -> replacement `e3b0c44298fc1c14`
* verdict: **KILLED**

Anchor:
```rust
        view.put(
            cf::PROPERTY_COVERAGE,
            coverage_key(&coverage.coverage_id),
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
test every_dependent_row_finds_its_parent_within_one_block ... FAILED
```

#### C5 claim row not written

* occurrences checked before applying: **1** (expected 1)
* covering test: `every_dependent_row_finds_its_parent_within_one_block` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `481a883aa9c40f13` -> replacement `e3b0c44298fc1c14`
* verdict: **KILLED**

Anchor:
```rust
        view.put(cf::PROPERTY_CLAIMS, claim_key(&claim.claim_id), &bytes)
            .map_err(StateError::Storage)?;
```
Replacement:
```rust
(deleted)
```
Printed by libtest while mutated:
```
test every_dependent_row_finds_its_parent_within_one_block ... FAILED
```

#### C6 proof row not written

* occurrences checked before applying: **1** (expected 1)
* covering test: `an_abandoned_block_leaves_all_eleven_families_untouched` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `d61b56346ece5f56` -> replacement `b17e351a96d51a7c`
* verdict: **KILLED**

Anchor:
```rust
        view.put(
            cf::PROPERTY_PROOFS,
            property_proof_key(&proof.proof_id),
            &bytes,
        )
        .map_err(StateError::Storage)
```
Replacement:
```rust
        Ok(())
```
Printed by libtest while mutated:
```
test an_abandoned_block_leaves_all_eleven_families_untouched ... FAILED
```

#### C7 jurisdiction index never appended

* occurrences checked before applying: **1** (expected 1)
* covering test: `all_five_indexes_accumulate_within_one_block` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `cd5e0f25f8f9fffa` -> replacement `4300a7f173053755`
* verdict: **KILLED**

Anchor:
```rust
        Self::v_add_to_jurisdiction_index(view, &asset.jurisdiction_code, &asset.asset_id)
    }
```
Replacement:
```rust
        Ok(())
    }
```
Printed by libtest while mutated:
```
test all_five_indexes_accumulate_within_one_block ... FAILED
```

#### C8 asset-title index never appended

* occurrences checked before applying: **1** (expected 1)
* covering test: `all_five_indexes_accumulate_within_one_block` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `a1f6704fc42ac264` -> replacement `4300a7f173053755`
* verdict: **KILLED**

Anchor:
```rust
        Self::v_add_to_asset_title_index(view, &event.asset_id, &event.event_id)
    }
```
Replacement:
```rust
        Ok(())
    }
```
Printed by libtest while mutated:
```
test all_five_indexes_accumulate_within_one_block ... FAILED
```

#### C9 asset-encumbrance index never appended

* occurrences checked before applying: **1** (expected 1)
* covering test: `all_five_indexes_accumulate_within_one_block` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `769f5e45a4202118` -> replacement `4300a7f173053755`
* verdict: **KILLED**

Anchor:
```rust
        Self::v_add_to_asset_encumbrance_index(
            view,
            &encumbrance.asset_id,
            &encumbrance.encumbrance_id,
        )
    }
```
Replacement:
```rust
        Ok(())
    }
```
Printed by libtest while mutated:
```
test all_five_indexes_accumulate_within_one_block ... FAILED
```

#### C10 asset-coverage index never appended

* occurrences checked before applying: **1** (expected 1)
* covering test: `all_five_indexes_accumulate_within_one_block` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `b0781100f4a5ad2f` -> replacement `4300a7f173053755`
* verdict: **KILLED**

Anchor:
```rust
        Self::v_add_to_asset_coverage_index(view, &coverage.asset_id, &coverage.coverage_id)
    }
```
Replacement:
```rust
        Ok(())
    }
```
Printed by libtest while mutated:
```
test all_five_indexes_accumulate_within_one_block ... FAILED
```

#### C11 coverage-claim index never appended

* occurrences checked before applying: **1** (expected 1)
* covering test: `all_five_indexes_accumulate_within_one_block` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `957398a1d3e437d0` -> replacement `4300a7f173053755`
* verdict: **KILLED**

Anchor:
```rust
        Self::v_add_to_coverage_claim_index(view, &claim.coverage_id, &claim.claim_id)
    }
```
Replacement:
```rust
        Ok(())
    }
```
Printed by libtest while mutated:
```
test all_five_indexes_accumulate_within_one_block ... FAILED
```

#### C12 jurisdiction index write dropped

* occurrences checked before applying: **1** (expected 1)
* covering test: `all_five_indexes_accumulate_within_one_block` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `1ba98180692cd659` -> replacement `4300a7f173053755`
* verdict: **KILLED**

Anchor:
```rust
        view.put(
            cf::PROPERTY_JURISDICTION_INDEX,
            jurisdiction_index_key(jurisdiction),
            &bytes,
        )
        .map_err(StateError::Storage)
    }
```
Replacement:
```rust
        Ok(())
    }
```
Printed by libtest while mutated:
```
test all_five_indexes_accumulate_within_one_block ... FAILED
```

#### C13 asset-title index write dropped

* occurrences checked before applying: **1** (expected 1)
* covering test: `all_five_indexes_accumulate_within_one_block` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `ebbf7440bb1ec0cb` -> replacement `4300a7f173053755`
* verdict: **KILLED**

Anchor:
```rust
        view.put(
            cf::PROPERTY_ASSET_TITLE_INDEX,
            asset_title_index_key(asset_id),
            &bytes,
        )
        .map_err(StateError::Storage)
    }
```
Replacement:
```rust
        Ok(())
    }
```
Printed by libtest while mutated:
```
test all_five_indexes_accumulate_within_one_block ... FAILED
```

#### C14 asset-encumbrance index write dropped

* occurrences checked before applying: **1** (expected 1)
* covering test: `all_five_indexes_accumulate_within_one_block` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `011ba91dab84d839` -> replacement `4300a7f173053755`
* verdict: **KILLED**

Anchor:
```rust
        view.put(
            cf::PROPERTY_ASSET_ENCUMBRANCE_INDEX,
            asset_encumbrance_index_key(asset_id),
            &bytes,
        )
        .map_err(StateError::Storage)
    }
```
Replacement:
```rust
        Ok(())
    }
```
Printed by libtest while mutated:
```
test all_five_indexes_accumulate_within_one_block ... FAILED
```

#### C15 asset-coverage index write dropped

* occurrences checked before applying: **1** (expected 1)
* covering test: `all_five_indexes_accumulate_within_one_block` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `bd743c674a59e380` -> replacement `4300a7f173053755`
* verdict: **KILLED**

Anchor:
```rust
        view.put(
            cf::PROPERTY_ASSET_COVERAGE_INDEX,
            asset_coverage_index_key(asset_id),
            &bytes,
        )
        .map_err(StateError::Storage)
    }
```
Replacement:
```rust
        Ok(())
    }
```
Printed by libtest while mutated:
```
test all_five_indexes_accumulate_within_one_block ... FAILED
```

#### C16 coverage-claim index write dropped

* occurrences checked before applying: **1** (expected 1)
* covering test: `all_five_indexes_accumulate_within_one_block` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `da81a7b8627b7b3d` -> replacement `4300a7f173053755`
* verdict: **KILLED**

Anchor:
```rust
        view.put(
            cf::PROPERTY_COVERAGE_CLAIM_INDEX,
            coverage_claim_index_key(coverage_id),
            &bytes,
        )
        .map_err(StateError::Storage)
    }
```
Replacement:
```rust
        Ok(())
    }
```
Printed by libtest while mutated:
```
test all_five_indexes_accumulate_within_one_block ... FAILED
```

#### O1 asset index appended before the asset row

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_refusal_part_way_leaves_canonical_storage_untouched` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `ffdd927f696559fd` -> replacement `8b7a5c9c6ad5070d`
* verdict: **KILLED**

Anchor:
```rust
        view.put(cf::PROPERTY_ASSETS, asset_key(&asset.asset_id), &bytes)
            .map_err(StateError::Storage)?;
        Self::v_add_to_jurisdiction_index(view, &asset.jurisdiction_code, &asset.asset_id)
```
Replacement:
```rust
        Self::v_add_to_jurisdiction_index(view, &asset.jurisdiction_code, &asset.asset_id)?;
        view.put(cf::PROPERTY_ASSETS, asset_key(&asset.asset_id), &bytes)
            .map_err(StateError::Storage)
```
Printed by libtest while mutated:
```
test a_refusal_part_way_leaves_canonical_storage_untouched ... FAILED
```

#### O2 title index appended before the event row

* occurrences checked before applying: **1** (expected 1)
* covering test: `corrupt_rows_error_through_dispatch_with_exactly_this_staged` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `3638605f3da175f4` -> replacement `d4ba3d547da75fdf`
* verdict: **KILLED**

Anchor:
```rust
        view.put(
            cf::PROPERTY_TITLE_EVENTS,
            title_event_key(&event.event_id),
            &bytes,
        )
        .map_err(StateError::Storage)?;
        Self::v_add_to_asset_title_index(view, &event.asset_id, &event.event_id)
```
Replacement:
```rust
        Self::v_add_to_asset_title_index(view, &event.asset_id, &event.event_id)?;
        view.put(
            cf::PROPERTY_TITLE_EVENTS,
            title_event_key(&event.event_id),
            &bytes,
        )
        .map_err(StateError::Storage)
```
Printed by libtest while mutated:
```
test corrupt_rows_error_through_dispatch_with_exactly_this_staged ... FAILED
```

#### O3 encumbrance index appended before the row

* occurrences checked before applying: **1** (expected 1)
* covering test: `corrupt_rows_error_through_dispatch_with_exactly_this_staged` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `1ac890fe8f60c31a` -> replacement `34b43eeafb8ca3e5`
* verdict: **KILLED**

Anchor:
```rust
        view.put(
            cf::PROPERTY_ENCUMBRANCES,
            encumbrance_key(&encumbrance.encumbrance_id),
            &bytes,
        )
        .map_err(StateError::Storage)?;
        Self::v_add_to_asset_encumbrance_index(
            view,
            &encumbrance.asset_id,
            &encumbrance.encumbrance_id,
        )
```
Replacement:
```rust
        Self::v_add_to_asset_encumbrance_index(
            view,
            &encumbrance.asset_id,
            &encumbrance.encumbrance_id,
        )?;
        view.put(
            cf::PROPERTY_ENCUMBRANCES,
            encumbrance_key(&encumbrance.encumbrance_id),
            &bytes,
        )
        .map_err(StateError::Storage)
```
Printed by libtest while mutated:
```
test corrupt_rows_error_through_dispatch_with_exactly_this_staged ... FAILED
```

#### O4 coverage index appended before the row

* occurrences checked before applying: **1** (expected 1)
* covering test: `corrupt_rows_error_through_dispatch_with_exactly_this_staged` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `27f6c9f1f59c3ed3` -> replacement `1216317aa59b5cf9`
* verdict: **KILLED**

Anchor:
```rust
        view.put(
            cf::PROPERTY_COVERAGE,
            coverage_key(&coverage.coverage_id),
            &bytes,
        )
        .map_err(StateError::Storage)?;
        Self::v_add_to_asset_coverage_index(view, &coverage.asset_id, &coverage.coverage_id)
```
Replacement:
```rust
        Self::v_add_to_asset_coverage_index(view, &coverage.asset_id, &coverage.coverage_id)?;
        view.put(
            cf::PROPERTY_COVERAGE,
            coverage_key(&coverage.coverage_id),
            &bytes,
        )
        .map_err(StateError::Storage)
```
Printed by libtest while mutated:
```
test corrupt_rows_error_through_dispatch_with_exactly_this_staged ... FAILED
```

#### O5 claim index appended before the row

* occurrences checked before applying: **1** (expected 1)
* covering test: `corrupt_rows_error_through_dispatch_with_exactly_this_staged` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `fc595da323c134c8` -> replacement `0d1073c55154e760`
* verdict: **KILLED**

Anchor:
```rust
        view.put(cf::PROPERTY_CLAIMS, claim_key(&claim.claim_id), &bytes)
            .map_err(StateError::Storage)?;
        Self::v_add_to_coverage_claim_index(view, &claim.coverage_id, &claim.claim_id)
```
Replacement:
```rust
        Self::v_add_to_coverage_claim_index(view, &claim.coverage_id, &claim.claim_id)?;
        view.put(cf::PROPERTY_CLAIMS, claim_key(&claim.claim_id), &bytes)
            .map_err(StateError::Storage)
```
Printed by libtest while mutated:
```
test corrupt_rows_error_through_dispatch_with_exactly_this_staged ... FAILED
```

#### D1 asset transition writes nothing

* occurrences checked before applying: **1** (expected 1)
* covering test: `merge_subdivide_and_transfer_record_a_status_and_nothing_else` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `dabf14598feb5330` -> replacement `c9213d1f4230809a`
* verdict: **KILLED**

Anchor:
```rust
                view.put(cf::PROPERTY_ASSETS, asset_key(asset_id), &bytes)
                    .map_err(StateError::Storage)
```
Replacement:
```rust
                Ok(())
```
Printed by libtest while mutated:
```
test merge_subdivide_and_transfer_record_a_status_and_nothing_else ... FAILED
```

#### D2 title-event transition writes nothing

* occurrences checked before applying: **1** (expected 1)
* covering test: `every_remaining_status_transition_reads_the_row_the_one_before_it_staged` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `005d98ea6954d2c4` -> replacement `c9213d1f4230809a`
* verdict: **KILLED**

Anchor:
```rust
                view.put(cf::PROPERTY_TITLE_EVENTS, title_event_key(event_id), &bytes)
                    .map_err(StateError::Storage)
```
Replacement:
```rust
                Ok(())
```
Printed by libtest while mutated:
```
test every_remaining_status_transition_reads_the_row_the_one_before_it_staged ... FAILED
```

#### D3 encumbrance transition writes nothing

* occurrences checked before applying: **1** (expected 1)
* covering test: `every_remaining_status_transition_reads_the_row_the_one_before_it_staged` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `02dc2e6942049829` -> replacement `c9213d1f4230809a`
* verdict: **KILLED**

Anchor:
```rust
                view.put(
                    cf::PROPERTY_ENCUMBRANCES,
                    encumbrance_key(encumbrance_id),
                    &bytes,
                )
                .map_err(StateError::Storage)
```
Replacement:
```rust
                Ok(())
```
Printed by libtest while mutated:
```
test every_remaining_status_transition_reads_the_row_the_one_before_it_staged ... FAILED
```

#### D4 coverage transition writes nothing

* occurrences checked before applying: **1** (expected 1)
* covering test: `suspend_then_reinstate_in_one_block_reactivates_the_coverage` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `bb91bd1b7f26012f` -> replacement `02d582d4b1496e92`
* verdict: **KILLED**

Anchor:
```rust
                coverage.status = status;
                coverage.updated_at = timestamp;
                let bytes = encode_coverage(&coverage).map_err(StateError::Storage)?;
                view.put(cf::PROPERTY_COVERAGE, coverage_key(coverage_id), &bytes)
                    .map_err(StateError::Storage)
```
Replacement:
```rust
                coverage.status = status;
                coverage.updated_at = timestamp;
                let _ = encode_coverage(&coverage).map_err(StateError::Storage)?;
                Ok(())
```
Printed by libtest while mutated:
```
test suspend_then_reinstate_in_one_block_reactivates_the_coverage ... FAILED
```

#### D5 renewal writes nothing

* occurrences checked before applying: **1** (expected 1)
* covering test: `the_block_timestamp_reaching_property_operations_is_always_zero` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `616773b88ec36954` -> replacement `954e48fcd7df690e`
* verdict: **KILLED**

Anchor:
```rust
                coverage.status = CoverageStatus::Renewed;
                coverage.updated_at = timestamp;
                let bytes = encode_coverage(&coverage).map_err(StateError::Storage)?;
                view.put(cf::PROPERTY_COVERAGE, coverage_key(coverage_id), &bytes)
                    .map_err(StateError::Storage)
```
Replacement:
```rust
                coverage.status = CoverageStatus::Renewed;
                coverage.updated_at = timestamp;
                let _ = encode_coverage(&coverage).map_err(StateError::Storage)?;
                Ok(())
```
Printed by libtest while mutated:
```
test the_block_timestamp_reaching_property_operations_is_always_zero ... FAILED
```

#### D6 claim transition writes nothing

* occurrences checked before applying: **1** (expected 1)
* covering test: `close_then_reopen_in_one_block_reopens_the_claim` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `a978d4e5bbbe9f3a` -> replacement `89b4f61d6a659ed1`
* verdict: **KILLED**

Anchor:
```rust
                claim.status = status;
                claim.updated_at = timestamp;
                let bytes = encode_claim(&claim).map_err(StateError::Storage)?;
                view.put(cf::PROPERTY_CLAIMS, claim_key(claim_id), &bytes)
                    .map_err(StateError::Storage)
```
Replacement:
```rust
                claim.status = status;
                claim.updated_at = timestamp;
                let _ = encode_claim(&claim).map_err(StateError::Storage)?;
                Ok(())
```
Printed by libtest while mutated:
```
test close_then_reopen_in_one_block_reopens_the_claim ... FAILED
```

#### D7 approval writes nothing

* occurrences checked before applying: **1** (expected 1)
* covering test: `approve_then_pay_in_one_block_records_both_commitments` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `4f925c822411bc16` -> replacement `932b3c9379600967`
* verdict: **KILLED**

Anchor:
```rust
                claim.status = ClaimStatus::Approved;
                claim.updated_at = timestamp;
                let bytes = encode_claim(&claim).map_err(StateError::Storage)?;
                view.put(cf::PROPERTY_CLAIMS, claim_key(claim_id), &bytes)
                    .map_err(StateError::Storage)
```
Replacement:
```rust
                claim.status = ClaimStatus::Approved;
                claim.updated_at = timestamp;
                let _ = encode_claim(&claim).map_err(StateError::Storage)?;
                Ok(())
```
Printed by libtest while mutated:
```
test approve_then_pay_in_one_block_records_both_commitments ... FAILED
```

#### D8 payment writes nothing

* occurrences checked before applying: **1** (expected 1)
* covering test: `approve_then_pay_in_one_block_records_both_commitments` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `749656100d2be46a` -> replacement `0d8a69e0f131b53e`
* verdict: **KILLED**

Anchor:
```rust
                claim.status = ClaimStatus::Paid;
                claim.updated_at = timestamp;
                let bytes = encode_claim(&claim).map_err(StateError::Storage)?;
                view.put(cf::PROPERTY_CLAIMS, claim_key(claim_id), &bytes)
                    .map_err(StateError::Storage)
```
Replacement:
```rust
                claim.status = ClaimStatus::Paid;
                claim.updated_at = timestamp;
                let _ = encode_claim(&claim).map_err(StateError::Storage)?;
                Ok(())
```
Printed by libtest while mutated:
```
test approve_then_pay_in_one_block_records_both_commitments ... FAILED
```

#### E1 title-event transition leaves created_at alone

* occurrences checked before applying: **1** (expected 1)
* covering test: `the_block_timestamp_reaching_property_operations_is_always_zero` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `107e63ddff9aeacd` -> replacement `e3b0c44298fc1c14`
* verdict: **KILLED**

Anchor:
```rust
                event.created_at = timestamp;
```
Replacement:
```rust
(deleted)
```
Printed by libtest while mutated:
```
test the_block_timestamp_reaching_property_operations_is_always_zero ... FAILED
```

#### E2 renewal does not set Renewed

* occurrences checked before applying: **1** (expected 1)
* covering test: `the_block_timestamp_reaching_property_operations_is_always_zero` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `06e45435b088fa0c` -> replacement `e3b0c44298fc1c14`
* verdict: **KILLED**

Anchor:
```rust
                coverage.status = CoverageStatus::Renewed;
```
Replacement:
```rust
(deleted)
```
Printed by libtest while mutated:
```
test the_block_timestamp_reaching_property_operations_is_always_zero ... FAILED
```

#### E3 renewal does not set the new expiry

* occurrences checked before applying: **1** (expected 1)
* covering test: `the_block_timestamp_reaching_property_operations_is_always_zero` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `237aaac235f353b2` -> replacement `e3b0c44298fc1c14`
* verdict: **KILLED**

Anchor:
```rust
                coverage.expiry = new_expiry;
```
Replacement:
```rust
(deleted)
```
Printed by libtest while mutated:
```
test the_block_timestamp_reaching_property_operations_is_always_zero ... FAILED
```

#### E4 approval records no commitment

* occurrences checked before applying: **1** (expected 1)
* covering test: `approve_then_pay_in_one_block_records_both_commitments` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `e95866b8fae472b8` -> replacement `3fe35b734288de5e`
* verdict: **KILLED**

Anchor:
```rust
                claim.approved_amount_commitment = Some(approved_amount_commitment);
```
Replacement:
```rust
                claim.approved_amount_commitment = None;
```
Printed by libtest while mutated:
```
test approve_then_pay_in_one_block_records_both_commitments ... FAILED
```

#### E5 payment records no commitment

* occurrences checked before applying: **1** (expected 1)
* covering test: `approve_then_pay_in_one_block_records_both_commitments` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `307d4b28cdff7160` -> replacement `e8ebbbc7d38add25`
* verdict: **KILLED**

Anchor:
```rust
                claim.paid_amount_commitment = Some(paid_amount_commitment);
```
Replacement:
```rust
                claim.paid_amount_commitment = None;
```
Printed by libtest while mutated:
```
test approve_then_pay_in_one_block_records_both_commitments ... FAILED
```

#### E6 payment does not set Paid

* occurrences checked before applying: **1** (expected 1)
* covering test: `approve_then_pay_in_one_block_records_both_commitments` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `45400805fca43e90` -> replacement `e3b0c44298fc1c14`
* verdict: **KILLED**

Anchor:
```rust
                claim.status = ClaimStatus::Paid;
```
Replacement:
```rust
(deleted)
```
Printed by libtest while mutated:
```
test approve_then_pay_in_one_block_records_both_commitments ... FAILED
```

#### E7 approval does not set Approved

* occurrences checked before applying: **1** (expected 1)
* covering test: `approve_then_pay_in_one_block_records_both_commitments` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `30226e084092e030` -> replacement `e3b0c44298fc1c14`
* verdict: **KILLED**

Anchor:
```rust
                claim.status = ClaimStatus::Approved;
```
Replacement:
```rust
(deleted)
```
Printed by libtest while mutated:
```
test approve_then_pay_in_one_block_records_both_commitments ... FAILED
```

#### E8 asset transition leaves updated_at alone

* occurrences checked before applying: **1** (expected 1)
* covering test: `the_block_timestamp_reaching_property_operations_is_always_zero` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `b961be6b6097142c` -> replacement `e3b0c44298fc1c14`
* verdict: **KILLED**

Anchor:
```rust
                asset.updated_at = timestamp;
```
Replacement:
```rust
(deleted)
```
Printed by libtest while mutated:
```
test the_block_timestamp_reaching_property_operations_is_always_zero ... FAILED
```

#### F1 corrupt asset row reads as absent

* occurrences checked before applying: **1** (expected 1)
* covering test: `corrupt_rows_error_through_dispatch_with_exactly_this_staged` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `98d95d8eb10c7f09` -> replacement `c81b0caa163565de`
* verdict: **KILLED**

Anchor:
```rust
            Some(bytes) => Ok(Some(decode_asset(&bytes).map_err(StateError::Storage)?)),
```
Replacement:
```rust
            Some(bytes) => Ok(decode_asset(&bytes).ok()),
```
Printed by libtest while mutated:
```
test corrupt_rows_error_through_dispatch_with_exactly_this_staged ... FAILED
```

#### F2 corrupt title-event row reads as absent

* occurrences checked before applying: **1** (expected 1)
* covering test: `corrupt_rows_error_through_dispatch_with_exactly_this_staged` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `6b065154c1860cf1` -> replacement `6d1022a4478542b5`
* verdict: **KILLED**

Anchor:
```rust
            Some(bytes) => Ok(Some(
                decode_title_event(&bytes).map_err(StateError::Storage)?,
            )),
```
Replacement:
```rust
            Some(bytes) => Ok(decode_title_event(&bytes).ok()),
```
Printed by libtest while mutated:
```
test corrupt_rows_error_through_dispatch_with_exactly_this_staged ... FAILED
```

#### F3 corrupt encumbrance row reads as absent

* occurrences checked before applying: **1** (expected 1)
* covering test: `corrupt_rows_error_through_dispatch_with_exactly_this_staged` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `039ff58d41058b22` -> replacement `0fcf357059042873`
* verdict: **KILLED**

Anchor:
```rust
            Some(bytes) => Ok(Some(
                decode_encumbrance(&bytes).map_err(StateError::Storage)?,
            )),
```
Replacement:
```rust
            Some(bytes) => Ok(decode_encumbrance(&bytes).ok()),
```
Printed by libtest while mutated:
```
test corrupt_rows_error_through_dispatch_with_exactly_this_staged ... FAILED
```

#### F4 corrupt coverage row reads as absent

* occurrences checked before applying: **1** (expected 1)
* covering test: `corrupt_rows_error_through_dispatch_with_exactly_this_staged` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `7a720a41b8689864` -> replacement `0d266f1ed43fb7f1`
* verdict: **KILLED**

Anchor:
```rust
            Some(bytes) => Ok(Some(decode_coverage(&bytes).map_err(StateError::Storage)?)),
```
Replacement:
```rust
            Some(bytes) => Ok(decode_coverage(&bytes).ok()),
```
Printed by libtest while mutated:
```
test corrupt_rows_error_through_dispatch_with_exactly_this_staged ... FAILED
```

#### F5 corrupt claim row reads as absent

* occurrences checked before applying: **1** (expected 1)
* covering test: `corrupt_rows_error_through_dispatch_with_exactly_this_staged` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `1b125b2a71f9587a` -> replacement `2bddfae78ab2de3e`
* verdict: **KILLED**

Anchor:
```rust
            Some(bytes) => Ok(Some(decode_claim(&bytes).map_err(StateError::Storage)?)),
```
Replacement:
```rust
            Some(bytes) => Ok(decode_claim(&bytes).ok()),
```
Printed by libtest while mutated:
```
test corrupt_rows_error_through_dispatch_with_exactly_this_staged ... FAILED
```

#### F6 corrupt jurisdiction index reads as empty

* occurrences checked before applying: **1** (expected 1)
* covering test: `corrupt_rows_error_through_dispatch_with_exactly_this_staged` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `8cfdbe48c4a83885` -> replacement `88c52a15aa71da6d`
* verdict: **KILLED**

Anchor:
```rust
            Some(bytes) => decode_jurisdiction_asset_ids(&bytes).map_err(StateError::Storage),
```
Replacement:
```rust
            Some(bytes) => Ok(decode_jurisdiction_asset_ids(&bytes).unwrap_or_default()),
```
Printed by libtest while mutated:
```
test corrupt_rows_error_through_dispatch_with_exactly_this_staged ... FAILED
```

#### F7 corrupt asset-title index reads as empty

* occurrences checked before applying: **1** (expected 1)
* covering test: `corrupt_rows_error_through_dispatch_with_exactly_this_staged` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `aceb58f562eaade0` -> replacement `2c5cf4a1cb0ab7d7`
* verdict: **KILLED**

Anchor:
```rust
            Some(bytes) => decode_asset_title_event_ids(&bytes).map_err(StateError::Storage),
```
Replacement:
```rust
            Some(bytes) => Ok(decode_asset_title_event_ids(&bytes).unwrap_or_default()),
```
Printed by libtest while mutated:
```
test corrupt_rows_error_through_dispatch_with_exactly_this_staged ... FAILED
```

#### F8 corrupt asset-encumbrance index reads as empty

* occurrences checked before applying: **1** (expected 1)
* covering test: `corrupt_rows_error_through_dispatch_with_exactly_this_staged` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `f88036f2143b7f0f` -> replacement `efc3884b4dc6570b`
* verdict: **KILLED**

Anchor:
```rust
            Some(bytes) => decode_asset_encumbrance_ids(&bytes).map_err(StateError::Storage),
```
Replacement:
```rust
            Some(bytes) => Ok(decode_asset_encumbrance_ids(&bytes).unwrap_or_default()),
```
Printed by libtest while mutated:
```
test corrupt_rows_error_through_dispatch_with_exactly_this_staged ... FAILED
```

#### F9 corrupt asset-coverage index reads as empty

* occurrences checked before applying: **1** (expected 1)
* covering test: `corrupt_rows_error_through_dispatch_with_exactly_this_staged` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `00b1b66da906196e` -> replacement `2eaa7c8932a9eb31`
* verdict: **KILLED**

Anchor:
```rust
            Some(bytes) => decode_asset_coverage_ids(&bytes).map_err(StateError::Storage),
```
Replacement:
```rust
            Some(bytes) => Ok(decode_asset_coverage_ids(&bytes).unwrap_or_default()),
```
Printed by libtest while mutated:
```
test corrupt_rows_error_through_dispatch_with_exactly_this_staged ... FAILED
```

#### F10 corrupt coverage-claim index reads as empty

* occurrences checked before applying: **1** (expected 1)
* covering test: `corrupt_rows_error_through_dispatch_with_exactly_this_staged` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `6cf0be747981525e` -> replacement `fe5f8b3fdc4ac04f`
* verdict: **KILLED**

Anchor:
```rust
            Some(bytes) => decode_coverage_claim_ids(&bytes).map_err(StateError::Storage),
```
Replacement:
```rust
            Some(bytes) => Ok(decode_coverage_claim_ids(&bytes).unwrap_or_default()),
```
Printed by libtest while mutated:
```
test corrupt_rows_error_through_dispatch_with_exactly_this_staged ... FAILED
```

### `crates/state/src/property_executor.rs`


#### J1 VerifyProof actually refuses

* occurrences checked before applying: **1** (expected 1)
* covering test: `verify_proof_succeeds_for_a_proof_that_does_not_exist` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `7fa1c204fbe5590d` -> replacement `e74a24ffdbbf0d52`
* verdict: **KILLED**

Anchor:
```rust
                debug!("Property proof verification requested by: {}", sender);
                Ok(PropertyExecutionResult::success())
```
Replacement:
```rust
                debug!("Property proof verification requested by: {}", sender);
                Ok(PropertyExecutionResult::failure("Proof not found"))
```
Printed by libtest while mutated:
```
test verify_proof_succeeds_for_a_proof_that_does_not_exist ... FAILED
```

#### J2 MergeAssets gains an issuer check

* occurrences checked before applying: **1** (expected 1)
* covering test: `three_operations_check_no_authority_at_all` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `a13aa47a2657a359` -> replacement `834c781d5e068b9a`
* verdict: **KILLED**

Anchor:
```rust
                if Self::v_get_asset(view, &d.primary_asset_id)?.is_none() {
                    return Ok(PropertyExecutionResult::failure("Primary asset not found"));
                }
```
Replacement:
```rust
                match Self::v_get_asset(view, &d.primary_asset_id)? {
                    None => {
                        return Ok(PropertyExecutionResult::failure("Primary asset not found"))
                    }
                    Some(a) if a.issuer_address != *sender => {
                        return Ok(PropertyExecutionResult::failure("Only issuer can merge"))
                    }
                    Some(_) => {}
                }
```
Printed by libtest while mutated:
```
test three_operations_check_no_authority_at_all ... FAILED
```

#### J3 SupersedeTitleEvent gains an issuer check

* occurrences checked before applying: **1** (expected 1)
* covering test: `three_operations_check_no_authority_at_all` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `635e28946a439e30` -> replacement `871f4acf476bb0f5`
* verdict: **KILLED**

Anchor:
```rust
                if Self::v_get_title_event(view, &d.old_event_id)?.is_none() {
                    return Ok(PropertyExecutionResult::failure("Old event not found"));
                }
```
Replacement:
```rust
                match Self::v_get_title_event(view, &d.old_event_id)? {
                    None => return Ok(PropertyExecutionResult::failure("Old event not found")),
                    Some(e) if e.issuer_address != *sender => {
                        return Ok(PropertyExecutionResult::failure("Only issuer can supersede"))
                    }
                    Some(_) => {}
                }
```
Printed by libtest while mutated:
```
test three_operations_check_no_authority_at_all ... FAILED
```

#### K1 TransferAsset writes the wrong status

* occurrences checked before applying: **1** (expected 1)
* covering test: `merge_subdivide_and_transfer_record_a_status_and_nothing_else` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `fb48f10c2a6fba84` -> replacement `b1739e4379a9fdfb`
* verdict: **KILLED**

Anchor:
```rust
                    AssetStatus::PendingTransfer,
```
Replacement:
```rust
                    AssetStatus::Seized,
```
Printed by libtest while mutated:
```
test merge_subdivide_and_transfer_record_a_status_and_nothing_else ... FAILED
```

#### K2 MergeAssets writes the wrong status

* occurrences checked before applying: **1** (expected 1)
* covering test: `three_operations_check_no_authority_at_all` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `88831e493ff4b5ce` -> replacement `b1739e4379a9fdfb`
* verdict: **KILLED**

Anchor:
```rust
                    AssetStatus::Merged,
```
Replacement:
```rust
                    AssetStatus::Seized,
```
Printed by libtest while mutated:
```
test three_operations_check_no_authority_at_all ... FAILED
```

#### K3 SubdivideAsset writes the wrong status

* occurrences checked before applying: **1** (expected 1)
* covering test: `merge_subdivide_and_transfer_record_a_status_and_nothing_else` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `c453635c89cd680d` -> replacement `b1739e4379a9fdfb`
* verdict: **KILLED**

Anchor:
```rust
                    AssetStatus::Subdivided,
```
Replacement:
```rust
                    AssetStatus::Seized,
```
Printed by libtest while mutated:
```
test merge_subdivide_and_transfer_record_a_status_and_nothing_else ... FAILED
```

#### K4 DeregisterAsset writes the wrong status

* occurrences checked before applying: **1** (expected 1)
* covering test: `every_remaining_status_transition_reads_the_row_the_one_before_it_staged` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `cc42f64e77ee0f3e` -> replacement `b1739e4379a9fdfb`
* verdict: **KILLED**

Anchor:
```rust
                    AssetStatus::Deregistered,
```
Replacement:
```rust
                    AssetStatus::Seized,
```
Printed by libtest while mutated:
```
test every_remaining_status_transition_reads_the_row_the_one_before_it_staged ... FAILED
```

#### K5 VoidTitleEvent writes the wrong status

* occurrences checked before applying: **1** (expected 1)
* covering test: `the_block_timestamp_reaching_property_operations_is_always_zero` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `b93d8f0fd29b47ad` -> replacement `c700987dce1f8216`
* verdict: **KILLED**

Anchor:
```rust
                    TitleEventStatus::Voided,
```
Replacement:
```rust
                    TitleEventStatus::Pending,
```
Printed by libtest while mutated:
```
test the_block_timestamp_reaching_property_operations_is_always_zero ... FAILED
```

#### K6 SupersedeTitleEvent writes the wrong status

* occurrences checked before applying: **1** (expected 1)
* covering test: `three_operations_check_no_authority_at_all` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `035d69e4695cc2a5` -> replacement `c700987dce1f8216`
* verdict: **KILLED**

Anchor:
```rust
                    TitleEventStatus::Superseded,
```
Replacement:
```rust
                    TitleEventStatus::Pending,
```
Printed by libtest while mutated:
```
test three_operations_check_no_authority_at_all ... FAILED
```

#### K7 SubordinateEncumbrance writes the wrong status

* occurrences checked before applying: **1** (expected 1)
* covering test: `every_remaining_status_transition_reads_the_row_the_one_before_it_staged` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `8291a45a49a780a2` -> replacement `72fb227d479c8648`
* verdict: **KILLED**

Anchor:
```rust
                    EncumbranceStatus::Subordinated,
```
Replacement:
```rust
                    EncumbranceStatus::Expired,
```
Printed by libtest while mutated:
```
test every_remaining_status_transition_reads_the_row_the_one_before_it_staged ... FAILED
```

#### K8 ReleaseEncumbrance writes the wrong status

* occurrences checked before applying: **1** (expected 1)
* covering test: `every_remaining_status_transition_reads_the_row_the_one_before_it_staged` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `7a2fda26538250c2` -> replacement `72fb227d479c8648`
* verdict: **KILLED**

Anchor:
```rust
                    EncumbranceStatus::Released,
```
Replacement:
```rust
                    EncumbranceStatus::Expired,
```
Printed by libtest while mutated:
```
test every_remaining_status_transition_reads_the_row_the_one_before_it_staged ... FAILED
```

#### K9 ForecloseEncumbrance writes the wrong status

* occurrences checked before applying: **1** (expected 1)
* covering test: `every_remaining_status_transition_reads_the_row_the_one_before_it_staged` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `b4ee5b3fa42e97b8` -> replacement `72fb227d479c8648`
* verdict: **KILLED**

Anchor:
```rust
                    EncumbranceStatus::Foreclosed,
```
Replacement:
```rust
                    EncumbranceStatus::Expired,
```
Printed by libtest while mutated:
```
test every_remaining_status_transition_reads_the_row_the_one_before_it_staged ... FAILED
```

#### K10 CancelCoverage writes the wrong status

* occurrences checked before applying: **1** (expected 1)
* covering test: `every_remaining_status_transition_reads_the_row_the_one_before_it_staged` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `f862fd20a79239d7` -> replacement `2c4fba9c46267789`
* verdict: **KILLED**

Anchor:
```rust
                    CoverageStatus::Cancelled,
```
Replacement:
```rust
                    CoverageStatus::Expired,
```
Printed by libtest while mutated:
```
test every_remaining_status_transition_reads_the_row_the_one_before_it_staged ... FAILED
```

#### K11 SuspendCoverage writes the wrong status

* occurrences checked before applying: **1** (expected 1)
* covering test: `suspend_then_reinstate_in_one_block_reactivates_the_coverage` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `3ce644c81a90e4e3` -> replacement `2c4fba9c46267789`
* verdict: **KILLED**

Anchor:
```rust
                    CoverageStatus::Suspended,
```
Replacement:
```rust
                    CoverageStatus::Expired,
```
Printed by libtest while mutated:
```
test suspend_then_reinstate_in_one_block_reactivates_the_coverage ... FAILED
```

#### K12 ReinstateCoverage writes the wrong status

* occurrences checked before applying: **1** (expected 1)
* covering test: `suspend_then_reinstate_in_one_block_reactivates_the_coverage` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `9a46c85a789b384b` -> replacement `2c4fba9c46267789`
* verdict: **KILLED**

Anchor:
```rust
                    CoverageStatus::Active,
```
Replacement:
```rust
                    CoverageStatus::Expired,
```
Printed by libtest while mutated:
```
test suspend_then_reinstate_in_one_block_reactivates_the_coverage ... FAILED
```

#### K13 DenyClaim writes the wrong status

* occurrences checked before applying: **1** (expected 1)
* covering test: `every_remaining_status_transition_reads_the_row_the_one_before_it_staged` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `d73f66fd1ce5400c` -> replacement `3f6c086738fa3b60`
* verdict: **KILLED**

Anchor:
```rust
                    ClaimStatus::Denied,
```
Replacement:
```rust
                    ClaimStatus::Acknowledged,
```
Printed by libtest while mutated:
```
test every_remaining_status_transition_reads_the_row_the_one_before_it_staged ... FAILED
```

#### K14 CloseClaim writes the wrong status

* occurrences checked before applying: **1** (expected 1)
* covering test: `close_then_reopen_in_one_block_reopens_the_claim` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `2adf30f24ef7bb10` -> replacement `3f6c086738fa3b60`
* verdict: **KILLED**

Anchor:
```rust
                    ClaimStatus::Closed,
```
Replacement:
```rust
                    ClaimStatus::Acknowledged,
```
Printed by libtest while mutated:
```
test close_then_reopen_in_one_block_reopens_the_claim ... FAILED
```

#### K15 ReopenClaim writes the wrong status

* occurrences checked before applying: **1** (expected 1)
* covering test: `close_then_reopen_in_one_block_reopens_the_claim` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `061d22f4b2333cef` -> replacement `3f6c086738fa3b60`
* verdict: **KILLED**

Anchor:
```rust
                    ClaimStatus::Reopened,
```
Replacement:
```rust
                    ClaimStatus::Acknowledged,
```
Printed by libtest while mutated:
```
test close_then_reopen_in_one_block_reopens_the_claim ... FAILED
```

#### K16 WithdrawClaim writes the wrong status

* occurrences checked before applying: **1** (expected 1)
* covering test: `every_remaining_status_transition_reads_the_row_the_one_before_it_staged` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `9b884bed53f9ad5b` -> replacement `3f6c086738fa3b60`
* verdict: **KILLED**

Anchor:
```rust
                    ClaimStatus::Withdrawn,
```
Replacement:
```rust
                    ClaimStatus::Acknowledged,
```
Printed by libtest while mutated:
```
test every_remaining_status_transition_reads_the_row_the_one_before_it_staged ... FAILED
```

### `crates/storage/src/property_store.rs`


#### G1 asset key truncated

* occurrences checked before applying: **1** (expected 1)
* covering test: `an_asset_row_is_bincode_at_the_asset_id_key_and_indexes_its_jurisdiction` (`sumchain-storage --test property_codec_parity`)
* anchor sha256[:16] `be690c5fbbfd481c` -> replacement `cc37e0c8e6d4b7f7`
* verdict: **KILLED**

Anchor:
```rust
pub fn asset_key(asset_id: &AssetId) -> &[u8] {
    asset_id
}
```
Replacement:
```rust
pub fn asset_key(asset_id: &AssetId) -> &[u8] {
    &asset_id[..16]
}
```
Printed by libtest while mutated:
```
test an_asset_row_is_bincode_at_the_asset_id_key_and_indexes_its_jurisdiction ... FAILED
```

#### G3 title-event key truncated

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_title_event_row_is_bincode_at_the_event_id_key_and_indexes_its_asset` (`sumchain-storage --test property_codec_parity`)
* anchor sha256[:16] `35375876998d7ec9` -> replacement `a3ea89a7ca9a5cb7`
* verdict: **KILLED**

Anchor:
```rust
pub fn title_event_key(event_id: &TitleEventId) -> &[u8] {
    event_id
}
```
Replacement:
```rust
pub fn title_event_key(event_id: &TitleEventId) -> &[u8] {
    &event_id[..16]
}
```
Printed by libtest while mutated:
```
test a_title_event_row_is_bincode_at_the_event_id_key_and_indexes_its_asset ... FAILED
```

#### G4 asset-title index key truncated

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_title_event_row_is_bincode_at_the_event_id_key_and_indexes_its_asset` (`sumchain-storage --test property_codec_parity`)
* anchor sha256[:16] `7af0e514efe6fc14` -> replacement `7fd86703f841ba83`
* verdict: **KILLED**

Anchor:
```rust
pub fn asset_title_index_key(asset_id: &AssetId) -> &[u8] {
    asset_id
}
```
Replacement:
```rust
pub fn asset_title_index_key(asset_id: &AssetId) -> &[u8] {
    &asset_id[..16]
}
```
Printed by libtest while mutated:
```
test a_title_event_row_is_bincode_at_the_event_id_key_and_indexes_its_asset ... FAILED
```

#### G5 encumbrance key truncated

* occurrences checked before applying: **1** (expected 1)
* covering test: `an_encumbrance_row_is_bincode_at_its_id_key_and_indexes_its_asset` (`sumchain-storage --test property_codec_parity`)
* anchor sha256[:16] `349e6bdebfc114a7` -> replacement `35ed20210789b2aa`
* verdict: **KILLED**

Anchor:
```rust
pub fn encumbrance_key(encumbrance_id: &EncumbranceId) -> &[u8] {
    encumbrance_id
}
```
Replacement:
```rust
pub fn encumbrance_key(encumbrance_id: &EncumbranceId) -> &[u8] {
    &encumbrance_id[..16]
}
```
Printed by libtest while mutated:
```
test an_encumbrance_row_is_bincode_at_its_id_key_and_indexes_its_asset ... FAILED
```

#### G6 asset-encumbrance index key truncated

* occurrences checked before applying: **1** (expected 1)
* covering test: `an_encumbrance_row_is_bincode_at_its_id_key_and_indexes_its_asset` (`sumchain-storage --test property_codec_parity`)
* anchor sha256[:16] `a31e5a4713a401d2` -> replacement `13e2c9a207d26368`
* verdict: **KILLED**

Anchor:
```rust
pub fn asset_encumbrance_index_key(asset_id: &AssetId) -> &[u8] {
    asset_id
}
```
Replacement:
```rust
pub fn asset_encumbrance_index_key(asset_id: &AssetId) -> &[u8] {
    &asset_id[..16]
}
```
Printed by libtest while mutated:
```
test an_encumbrance_row_is_bincode_at_its_id_key_and_indexes_its_asset ... FAILED
```

#### G7 coverage key truncated

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_coverage_row_is_bincode_at_its_id_key_and_indexes_its_asset` (`sumchain-storage --test property_codec_parity`)
* anchor sha256[:16] `c1194a1ab82da059` -> replacement `cbf8cc363924fdce`
* verdict: **KILLED**

Anchor:
```rust
pub fn coverage_key(coverage_id: &CoverageId) -> &[u8] {
    coverage_id
}
```
Replacement:
```rust
pub fn coverage_key(coverage_id: &CoverageId) -> &[u8] {
    &coverage_id[..16]
}
```
Printed by libtest while mutated:
```
test a_coverage_row_is_bincode_at_its_id_key_and_indexes_its_asset ... FAILED
```

#### G8 asset-coverage index key truncated

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_coverage_row_is_bincode_at_its_id_key_and_indexes_its_asset` (`sumchain-storage --test property_codec_parity`)
* anchor sha256[:16] `fc82dfbad6817a9b` -> replacement `e1214b1c6a6ff1bd`
* verdict: **KILLED**

Anchor:
```rust
pub fn asset_coverage_index_key(asset_id: &AssetId) -> &[u8] {
    asset_id
}
```
Replacement:
```rust
pub fn asset_coverage_index_key(asset_id: &AssetId) -> &[u8] {
    &asset_id[..16]
}
```
Printed by libtest while mutated:
```
test a_coverage_row_is_bincode_at_its_id_key_and_indexes_its_asset ... FAILED
```

#### G9 claim key truncated

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_claim_row_is_bincode_at_its_id_key_and_indexes_its_coverage` (`sumchain-storage --test property_codec_parity`)
* anchor sha256[:16] `5d666cf93ee98521` -> replacement `6482ac09428d370e`
* verdict: **KILLED**

Anchor:
```rust
pub fn claim_key(claim_id: &ClaimId) -> &[u8] {
    claim_id
}
```
Replacement:
```rust
pub fn claim_key(claim_id: &ClaimId) -> &[u8] {
    &claim_id[..16]
}
```
Printed by libtest while mutated:
```
test a_claim_row_is_bincode_at_its_id_key_and_indexes_its_coverage ... FAILED
```

#### G10 coverage-claim index key truncated

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_claim_row_is_bincode_at_its_id_key_and_indexes_its_coverage` (`sumchain-storage --test property_codec_parity`)
* anchor sha256[:16] `6cbfe029896d8837` -> replacement `c93039ece962a439`
* verdict: **KILLED**

Anchor:
```rust
pub fn coverage_claim_index_key(coverage_id: &CoverageId) -> &[u8] {
    coverage_id
}
```
Replacement:
```rust
pub fn coverage_claim_index_key(coverage_id: &CoverageId) -> &[u8] {
    &coverage_id[..16]
}
```
Printed by libtest while mutated:
```
test a_claim_row_is_bincode_at_its_id_key_and_indexes_its_coverage ... FAILED
```

#### G11 proof key truncated

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_proof_row_is_bincode_at_the_proof_id_key_and_writes_no_index` (`sumchain-storage --test property_codec_parity`)
* anchor sha256[:16] `e064097da4ac64bc` -> replacement `2f86952f0f767a94`
* verdict: **KILLED**

Anchor:
```rust
pub fn property_proof_key(proof_id: &ProofId) -> &[u8] {
    proof_id
}
```
Replacement:
```rust
pub fn property_proof_key(proof_id: &ProofId) -> &[u8] {
    &proof_id[..16]
}
```
Printed by libtest while mutated:
```
test a_proof_row_is_bincode_at_the_proof_id_key_and_writes_no_index ... FAILED
```

#### G2 jurisdiction index key truncated

* occurrences checked before applying: **1** (expected 1)
* covering test: `an_asset_row_is_bincode_at_the_asset_id_key_and_indexes_its_jurisdiction` (`sumchain-storage --test property_codec_parity`)
* anchor sha256[:16] `1baea50624867cda` -> replacement `25789009c13facb2`
* verdict: **KILLED**

Anchor:
```rust
pub fn jurisdiction_index_key(jurisdiction: &str) -> &[u8] {
    jurisdiction.as_bytes()
}
```
Replacement:
```rust
pub fn jurisdiction_index_key(jurisdiction: &str) -> &[u8] {
    &jurisdiction.as_bytes()[..2]
}
```
Printed by libtest while mutated:
```
test an_asset_row_is_bincode_at_the_asset_id_key_and_indexes_its_jurisdiction ... FAILED
```

#### H1 asset encoder writes nothing

* occurrences checked before applying: **1** (expected 1)
* covering test: `an_asset_row_is_bincode_at_the_asset_id_key_and_indexes_its_jurisdiction` (`sumchain-storage --test property_codec_parity`)
* anchor sha256[:16] `17af6ab14d09a98d` -> replacement `7ac6aac0edd272c3`
* verdict: **KILLED**

Anchor:
```rust
pub fn encode_asset(a: &AssetAnchor) -> Result<Vec<u8>> {
    bincode::serialize(a).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Replacement:
```rust
pub fn encode_asset(a: &AssetAnchor) -> Result<Vec<u8>> {
    let _ = a;
    Ok(Vec::new())
}
```
Printed by libtest while mutated:
```
test an_asset_row_is_bincode_at_the_asset_id_key_and_indexes_its_jurisdiction ... FAILED
```

#### H1d asset decoder never succeeds

* occurrences checked before applying: **1** (expected 1)
* covering test: `every_round_trip_returns_the_value_that_was_written` (`sumchain-storage --test property_codec_parity`)
* anchor sha256[:16] `55b211ae578e843f` -> replacement `6e276efacf942296`
* verdict: **KILLED**

Anchor:
```rust
pub fn decode_asset(bytes: &[u8]) -> Result<AssetAnchor> {
    bincode::deserialize(bytes).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Replacement:
```rust
pub fn decode_asset(bytes: &[u8]) -> Result<AssetAnchor> {
    let _ = bytes;
    bincode::deserialize(&Vec::<u8>::new())
        .map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Printed by libtest while mutated:
```
test every_round_trip_returns_the_value_that_was_written ... FAILED
```

#### H2 title event encoder writes nothing

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_title_event_row_is_bincode_at_the_event_id_key_and_indexes_its_asset` (`sumchain-storage --test property_codec_parity`)
* anchor sha256[:16] `b18cdc89abfdf958` -> replacement `6beb319e4c4577fe`
* verdict: **KILLED**

Anchor:
```rust
pub fn encode_title_event(e: &TitleEvent) -> Result<Vec<u8>> {
    bincode::serialize(e).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Replacement:
```rust
pub fn encode_title_event(e: &TitleEvent) -> Result<Vec<u8>> {
    let _ = e;
    Ok(Vec::new())
}
```
Printed by libtest while mutated:
```
test a_title_event_row_is_bincode_at_the_event_id_key_and_indexes_its_asset ... FAILED
```

#### H2d title event decoder never succeeds

* occurrences checked before applying: **1** (expected 1)
* covering test: `every_round_trip_returns_the_value_that_was_written` (`sumchain-storage --test property_codec_parity`)
* anchor sha256[:16] `4c5630fd19b5d8a7` -> replacement `f4ebef5345e32a94`
* verdict: **KILLED**

Anchor:
```rust
pub fn decode_title_event(bytes: &[u8]) -> Result<TitleEvent> {
    bincode::deserialize(bytes).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Replacement:
```rust
pub fn decode_title_event(bytes: &[u8]) -> Result<TitleEvent> {
    let _ = bytes;
    bincode::deserialize(&Vec::<u8>::new())
        .map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Printed by libtest while mutated:
```
test every_round_trip_returns_the_value_that_was_written ... FAILED
```

#### H3 encumbrance encoder writes nothing

* occurrences checked before applying: **1** (expected 1)
* covering test: `an_encumbrance_row_is_bincode_at_its_id_key_and_indexes_its_asset` (`sumchain-storage --test property_codec_parity`)
* anchor sha256[:16] `e29e339aa8aed68c` -> replacement `da949b16f0efecf1`
* verdict: **KILLED**

Anchor:
```rust
pub fn encode_encumbrance(e: &Encumbrance) -> Result<Vec<u8>> {
    bincode::serialize(e).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Replacement:
```rust
pub fn encode_encumbrance(e: &Encumbrance) -> Result<Vec<u8>> {
    let _ = e;
    Ok(Vec::new())
}
```
Printed by libtest while mutated:
```
test an_encumbrance_row_is_bincode_at_its_id_key_and_indexes_its_asset ... FAILED
```

#### H3d encumbrance decoder never succeeds

* occurrences checked before applying: **1** (expected 1)
* covering test: `every_round_trip_returns_the_value_that_was_written` (`sumchain-storage --test property_codec_parity`)
* anchor sha256[:16] `0a74118b579e0842` -> replacement `06ee013a9c869a67`
* verdict: **KILLED**

Anchor:
```rust
pub fn decode_encumbrance(bytes: &[u8]) -> Result<Encumbrance> {
    bincode::deserialize(bytes).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Replacement:
```rust
pub fn decode_encumbrance(bytes: &[u8]) -> Result<Encumbrance> {
    let _ = bytes;
    bincode::deserialize(&Vec::<u8>::new())
        .map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Printed by libtest while mutated:
```
test every_round_trip_returns_the_value_that_was_written ... FAILED
```

#### H4 coverage encoder writes nothing

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_coverage_row_is_bincode_at_its_id_key_and_indexes_its_asset` (`sumchain-storage --test property_codec_parity`)
* anchor sha256[:16] `d3b9a05e61023d8c` -> replacement `f1a8b511c477b5d6`
* verdict: **KILLED**

Anchor:
```rust
pub fn encode_coverage(c: &InsuranceCoverage) -> Result<Vec<u8>> {
    bincode::serialize(c).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Replacement:
```rust
pub fn encode_coverage(c: &InsuranceCoverage) -> Result<Vec<u8>> {
    let _ = c;
    Ok(Vec::new())
}
```
Printed by libtest while mutated:
```
test a_coverage_row_is_bincode_at_its_id_key_and_indexes_its_asset ... FAILED
```

#### H4d coverage decoder never succeeds

* occurrences checked before applying: **1** (expected 1)
* covering test: `every_round_trip_returns_the_value_that_was_written` (`sumchain-storage --test property_codec_parity`)
* anchor sha256[:16] `952a153d9507cc5c` -> replacement `f6240f573ac1130c`
* verdict: **KILLED**

Anchor:
```rust
pub fn decode_coverage(bytes: &[u8]) -> Result<InsuranceCoverage> {
    bincode::deserialize(bytes).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Replacement:
```rust
pub fn decode_coverage(bytes: &[u8]) -> Result<InsuranceCoverage> {
    let _ = bytes;
    bincode::deserialize(&Vec::<u8>::new())
        .map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Printed by libtest while mutated:
```
test every_round_trip_returns_the_value_that_was_written ... FAILED
```

#### H5 claim encoder writes nothing

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_claim_row_is_bincode_at_its_id_key_and_indexes_its_coverage` (`sumchain-storage --test property_codec_parity`)
* anchor sha256[:16] `a26dc0afea2c54e7` -> replacement `8f73be1e991e02c6`
* verdict: **KILLED**

Anchor:
```rust
pub fn encode_claim(c: &InsuranceClaim) -> Result<Vec<u8>> {
    bincode::serialize(c).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Replacement:
```rust
pub fn encode_claim(c: &InsuranceClaim) -> Result<Vec<u8>> {
    let _ = c;
    Ok(Vec::new())
}
```
Printed by libtest while mutated:
```
test a_claim_row_is_bincode_at_its_id_key_and_indexes_its_coverage ... FAILED
```

#### H5d claim decoder never succeeds

* occurrences checked before applying: **1** (expected 1)
* covering test: `every_round_trip_returns_the_value_that_was_written` (`sumchain-storage --test property_codec_parity`)
* anchor sha256[:16] `ca1e88d24d035160` -> replacement `b796475abb646eb7`
* verdict: **KILLED**

Anchor:
```rust
pub fn decode_claim(bytes: &[u8]) -> Result<InsuranceClaim> {
    bincode::deserialize(bytes).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Replacement:
```rust
pub fn decode_claim(bytes: &[u8]) -> Result<InsuranceClaim> {
    let _ = bytes;
    bincode::deserialize(&Vec::<u8>::new())
        .map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Printed by libtest while mutated:
```
test every_round_trip_returns_the_value_that_was_written ... FAILED
```

#### H6 proof encoder writes nothing

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_proof_row_is_bincode_at_the_proof_id_key_and_writes_no_index` (`sumchain-storage --test property_codec_parity`)
* anchor sha256[:16] `fd4acf6eef243db7` -> replacement `053300dc11464a9a`
* verdict: **KILLED**

Anchor:
```rust
pub fn encode_property_proof(p: &PropertyProofEnvelope) -> Result<Vec<u8>> {
    bincode::serialize(p).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Replacement:
```rust
pub fn encode_property_proof(p: &PropertyProofEnvelope) -> Result<Vec<u8>> {
    let _ = p;
    Ok(Vec::new())
}
```
Printed by libtest while mutated:
```
test a_proof_row_is_bincode_at_the_proof_id_key_and_writes_no_index ... FAILED
```

#### H6d proof decoder never succeeds

* occurrences checked before applying: **1** (expected 1)
* covering test: `every_round_trip_returns_the_value_that_was_written` (`sumchain-storage --test property_codec_parity`)
* anchor sha256[:16] `e0e09825d37a5dc0` -> replacement `69b29f37d5f58a85`
* verdict: **KILLED**

Anchor:
```rust
pub fn decode_property_proof(bytes: &[u8]) -> Result<PropertyProofEnvelope> {
    bincode::deserialize(bytes).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Replacement:
```rust
pub fn decode_property_proof(bytes: &[u8]) -> Result<PropertyProofEnvelope> {
    let _ = bytes;
    bincode::deserialize(&Vec::<u8>::new())
        .map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Printed by libtest while mutated:
```
test every_round_trip_returns_the_value_that_was_written ... FAILED
```

#### H7 jurisdiction index encoder reverses the list

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_second_asset_in_one_jurisdiction_appends_to_the_same_list` (`sumchain-storage --test property_codec_parity`)
* anchor sha256[:16] `e7ecc77cd92a1920` -> replacement `36843f6d92970220`
* verdict: **KILLED**

Anchor:
```rust
pub fn encode_jurisdiction_asset_ids(ids: &[AssetId]) -> Result<Vec<u8>> {
    bincode::serialize(ids).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Replacement:
```rust
pub fn encode_jurisdiction_asset_ids(ids: &[AssetId]) -> Result<Vec<u8>> {
    let mut reversed = ids.to_vec();
    reversed.reverse();
    bincode::serialize(&reversed).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Printed by libtest while mutated:
```
test a_second_asset_in_one_jurisdiction_appends_to_the_same_list ... FAILED
```

#### H7d jurisdiction index decoder reverses the list

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_second_asset_in_one_jurisdiction_appends_to_the_same_list` (`sumchain-storage --test property_codec_parity`)
* anchor sha256[:16] `304fe2c5467ae7d8` -> replacement `7e006ed796f0953a`
* verdict: **KILLED**

Anchor:
```rust
pub fn decode_jurisdiction_asset_ids(bytes: &[u8]) -> Result<Vec<AssetId>> {
    bincode::deserialize(bytes).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Replacement:
```rust
pub fn decode_jurisdiction_asset_ids(bytes: &[u8]) -> Result<Vec<AssetId>> {
    bincode::deserialize::<Vec<AssetId>>(bytes)
        .map(|mut v| {
            v.reverse();
            v
        })
        .map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Printed by libtest while mutated:
```
test a_second_asset_in_one_jurisdiction_appends_to_the_same_list ... FAILED
```

#### H8 asset-title index encoder reverses the list

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_second_title_event_for_one_asset_appends_to_the_same_list` (`sumchain-storage --test property_codec_parity`)
* anchor sha256[:16] `ec11fac56444cff5` -> replacement `0072942f7d9c2893`
* verdict: **KILLED**

Anchor:
```rust
pub fn encode_asset_title_event_ids(ids: &[TitleEventId]) -> Result<Vec<u8>> {
    bincode::serialize(ids).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Replacement:
```rust
pub fn encode_asset_title_event_ids(ids: &[TitleEventId]) -> Result<Vec<u8>> {
    let mut reversed = ids.to_vec();
    reversed.reverse();
    bincode::serialize(&reversed).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Printed by libtest while mutated:
```
test a_second_title_event_for_one_asset_appends_to_the_same_list ... FAILED
```

#### H8d asset-title index decoder reverses the list

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_second_title_event_for_one_asset_appends_to_the_same_list` (`sumchain-storage --test property_codec_parity`)
* anchor sha256[:16] `db490552e0f6ef41` -> replacement `594f3f265d835758`
* verdict: **KILLED**

Anchor:
```rust
pub fn decode_asset_title_event_ids(bytes: &[u8]) -> Result<Vec<TitleEventId>> {
    bincode::deserialize(bytes).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Replacement:
```rust
pub fn decode_asset_title_event_ids(bytes: &[u8]) -> Result<Vec<TitleEventId>> {
    bincode::deserialize::<Vec<TitleEventId>>(bytes)
        .map(|mut v| {
            v.reverse();
            v
        })
        .map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Printed by libtest while mutated:
```
test a_second_title_event_for_one_asset_appends_to_the_same_list ... FAILED
```

#### H9 asset-encumbrance index encoder reverses the list

* occurrences checked before applying: **1** (expected 1)
* covering test: `an_encumbrance_row_is_bincode_at_its_id_key_and_indexes_its_asset` (`sumchain-storage --test property_codec_parity`)
* anchor sha256[:16] `8b189e1fa2bbfbfe` -> replacement `1df9f1fa9eb69005`
* verdict: **KILLED**

Anchor:
```rust
pub fn encode_asset_encumbrance_ids(ids: &[EncumbranceId]) -> Result<Vec<u8>> {
    bincode::serialize(ids).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Replacement:
```rust
pub fn encode_asset_encumbrance_ids(ids: &[EncumbranceId]) -> Result<Vec<u8>> {
    let mut reversed = ids.to_vec();
    reversed.reverse();
    bincode::serialize(&reversed).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Printed by libtest while mutated:
```
test an_encumbrance_row_is_bincode_at_its_id_key_and_indexes_its_asset ... FAILED
```

#### H9d asset-encumbrance index decoder reverses the list

* occurrences checked before applying: **1** (expected 1)
* covering test: `an_encumbrance_row_is_bincode_at_its_id_key_and_indexes_its_asset` (`sumchain-storage --test property_codec_parity`)
* anchor sha256[:16] `919cf9d1b0e2a518` -> replacement `ef88495f8c8c1cba`
* verdict: **KILLED**

Anchor:
```rust
pub fn decode_asset_encumbrance_ids(bytes: &[u8]) -> Result<Vec<EncumbranceId>> {
    bincode::deserialize(bytes).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Replacement:
```rust
pub fn decode_asset_encumbrance_ids(bytes: &[u8]) -> Result<Vec<EncumbranceId>> {
    bincode::deserialize::<Vec<EncumbranceId>>(bytes)
        .map(|mut v| {
            v.reverse();
            v
        })
        .map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Printed by libtest while mutated:
```
test an_encumbrance_row_is_bincode_at_its_id_key_and_indexes_its_asset ... FAILED
```

#### H10 asset-coverage index encoder reverses the list

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_coverage_row_is_bincode_at_its_id_key_and_indexes_its_asset` (`sumchain-storage --test property_codec_parity`)
* anchor sha256[:16] `d581929b9b1a1f37` -> replacement `3fab0b338bd63f77`
* verdict: **KILLED**

Anchor:
```rust
pub fn encode_asset_coverage_ids(ids: &[CoverageId]) -> Result<Vec<u8>> {
    bincode::serialize(ids).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Replacement:
```rust
pub fn encode_asset_coverage_ids(ids: &[CoverageId]) -> Result<Vec<u8>> {
    let mut reversed = ids.to_vec();
    reversed.reverse();
    bincode::serialize(&reversed).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Printed by libtest while mutated:
```
test a_coverage_row_is_bincode_at_its_id_key_and_indexes_its_asset ... FAILED
```

#### H10d asset-coverage index decoder reverses the list

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_coverage_row_is_bincode_at_its_id_key_and_indexes_its_asset` (`sumchain-storage --test property_codec_parity`)
* anchor sha256[:16] `202b66ba561cdb68` -> replacement `0ffdccffdd7b1564`
* verdict: **KILLED**

Anchor:
```rust
pub fn decode_asset_coverage_ids(bytes: &[u8]) -> Result<Vec<CoverageId>> {
    bincode::deserialize(bytes).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Replacement:
```rust
pub fn decode_asset_coverage_ids(bytes: &[u8]) -> Result<Vec<CoverageId>> {
    bincode::deserialize::<Vec<CoverageId>>(bytes)
        .map(|mut v| {
            v.reverse();
            v
        })
        .map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Printed by libtest while mutated:
```
test a_coverage_row_is_bincode_at_its_id_key_and_indexes_its_asset ... FAILED
```

#### H11 coverage-claim index encoder reverses the list

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_claim_row_is_bincode_at_its_id_key_and_indexes_its_coverage` (`sumchain-storage --test property_codec_parity`)
* anchor sha256[:16] `5553095736954989` -> replacement `47f9bbde4e2a709f`
* verdict: **KILLED**

Anchor:
```rust
pub fn encode_coverage_claim_ids(ids: &[ClaimId]) -> Result<Vec<u8>> {
    bincode::serialize(ids).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Replacement:
```rust
pub fn encode_coverage_claim_ids(ids: &[ClaimId]) -> Result<Vec<u8>> {
    let mut reversed = ids.to_vec();
    reversed.reverse();
    bincode::serialize(&reversed).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Printed by libtest while mutated:
```
test a_claim_row_is_bincode_at_its_id_key_and_indexes_its_coverage ... FAILED
```

#### H11d coverage-claim index decoder reverses the list

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_claim_row_is_bincode_at_its_id_key_and_indexes_its_coverage` (`sumchain-storage --test property_codec_parity`)
* anchor sha256[:16] `73070b1e6d5307b7` -> replacement `663ddd677dc246d4`
* verdict: **KILLED**

Anchor:
```rust
pub fn decode_coverage_claim_ids(bytes: &[u8]) -> Result<Vec<ClaimId>> {
    bincode::deserialize(bytes).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Replacement:
```rust
pub fn decode_coverage_claim_ids(bytes: &[u8]) -> Result<Vec<ClaimId>> {
    bincode::deserialize::<Vec<ClaimId>>(bytes)
        .map(|mut v| {
            v.reverse();
            v
        })
        .map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Printed by libtest while mutated:
```
test a_claim_row_is_bincode_at_its_id_key_and_indexes_its_coverage ... FAILED
```

### `crates/state/src/executor.rs`


#### I1 live arm returns a neighbour's status code

* occurrences checked before applying: **1** (expected 1)
* covering test: `without_its_parent_each_dependent_row_is_refused` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `f65add06b1706b87` -> replacement `1107123bce3e01ca`
* verdict: **KILLED**

Anchor:
```rust
                                status: TxStatus::Failed(13), // Property operation failed
```
Replacement:
```rust
                                status: TxStatus::Failed(99), // Property operation failed
```
Printed by libtest while mutated:
```
test without_its_parent_each_dependent_row_is_refused ... FAILED
```

#### I2 v2 arm returns a neighbour's status code

* occurrences checked before applying: **1** (expected 1)
* covering test: `the_v2_dispatch_surface_also_stages_property_rows` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `5b10111fa1c6ecb8` -> replacement `03b4dc0547687b1c`
* verdict: **KILLED**

Anchor:
```rust
                        status: TxStatus::Failed(13), // Property operation failed
```
Replacement:
```rust
                        status: TxStatus::Failed(99), // Property operation failed
```
Printed by libtest while mutated:
```
test the_v2_dispatch_surface_also_stages_property_rows ... FAILED
```

#### I3 live arm forwards the real block timestamp

* occurrences checked before applying: **1** (expected 1)
* covering test: `the_block_timestamp_reaching_property_operations_is_always_zero` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `77d6710bd4f1e176` -> replacement `f9f6ea0739ce1877`
* verdict: **KILLED**

Anchor:
```rust
                        let result = PropertyExecutor::execute(
                            view,
                            &v2_tx.from,
                            &property_data,
                            proposer,
                            v2_tx.fee,
                            block_height,
                            0, // block_timestamp placeholder
```
Replacement:
```rust
                        let result = PropertyExecutor::execute(
                            view,
                            &v2_tx.from,
                            &property_data,
                            proposer,
                            v2_tx.fee,
                            block_height,
                            block_timestamp,
```
Printed by libtest while mutated:
```
test the_block_timestamp_reaching_property_operations_is_always_zero ... FAILED
```

#### I4 v2 arm forwards the real block timestamp

* occurrences checked before applying: **1** (expected 1)
* covering test: `the_v2_dispatch_surface_also_stages_property_rows` (`sumchain-state --test property_routing`)
* anchor sha256[:16] `77e7bae8e5aca6b7` -> replacement `3ca1637e6db247ba`
* verdict: **KILLED**

Anchor:
```rust
                let result = PropertyExecutor::execute(
                    view,
                    &tx.from,
                    property_data,
                    proposer,
                    tx.fee,
                    block_height,
                    0, // block_timestamp placeholder
```
Replacement:
```rust
                let result = PropertyExecutor::execute(
                    view,
                    &tx.from,
                    property_data,
                    proposer,
                    tx.fee,
                    block_height,
                    block_timestamp,
```
Printed by libtest while mutated:
```
test the_v2_dispatch_surface_also_stages_property_rows ... FAILED
```

## Totals and post-run hashes

```
=== totals ===
  killed: 119
  declared: 119   scored: 119

=== post-run hashes (authoritative) ===
  MATCH   aa088d5e1911a51bae0bc2a4df98adb7f32950d335c110ab0003512c4972f68c  crates/state/src/property_view.rs
  MATCH   117e19a10ac32dcdad83724eaed988027e9b9378af6c2ce29328ef9c775e8df0  crates/state/src/property_executor.rs
  MATCH   240c965975421c3aa8f6905014a18dade71fa3ceb00bf0c628c9044625fb3cf4  crates/state/src/executor.rs
  MATCH   82c25d7c033798fa3a5987ffae1fbd5276d00d2a8aaf7adaa64942d872e86f52  crates/storage/src/property_store.rs
  all four byte-identical to pre-run: True

=== anchors resolve exactly once again ===
  119/119
```


## Residue

```
=== 1. the four mutated files vs the pre-run backups ===
  MATCH  crates/state/src/property_view.rs  aa088d5e1911a51b
  MATCH  crates/state/src/property_executor.rs  117e19a10ac32dcd
  MATCH  crates/state/src/executor.rs  240c965975421c3a
  MATCH  crates/storage/src/property_store.rs  82c25d7c033798fa
  all four restored: True

=== 2. whole-crates scan, 88 specific replacements ===
  residue: NONE

  31 replacements are text that already occurs in the pristine
  tree and are covered by check 1 only -- a text scan for them is meaningless.

=== 3. every anchor still resolves exactly once ===
  anchors resolving once: 119/119; not-once: []
```
