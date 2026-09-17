# Healthcare routing: mutation battery

NOT DEPLOYABLE ON ITS OWN, like the rest of this lane.


Each mutation is applied to the tree that this commit contains, one at a time,
and the NAMED covering test is run. A kill requires that test to appear in
libtest's output AND to have failed. A mutation whose anchor does not resolve
exactly once aborts the whole run before anything is applied; one that does not
compile, and one whose covering test does not appear, are separate categories
that never count as kills. Restoration happens in a `finally` and on
SIGINT/SIGTERM, and every restore is checked against the pre-run hash. The whole
run is under `CARGO_INCREMENTAL=0`.

The repetitive anchors -- every candidate read, every `exists` guard, every
omitted write, every list decoder -- are not retyped here: they are sliced out
of the source file by the generator and then widened backwards, line by line,
until each resolves exactly once. Several of these `view.put` statements are
byte-identical across four different transitions, and only the preceding lines
of the same function tell them apart.

Whole-tree text scanning for leftover replacements is diagnostic only. A
replacement is usable as a residue marker only if it does not already occur in
the pristine tree; 30 of these do occur there -- strings such as
`Ok(false)`, `Ok(())` and outright deletions -- so finding them proves nothing.
The final evidence is 116 mutations total, 86 scanned specifically
by text, and 30 covered by exact file hashes alone. The
authoritative residue check for all 116 is the pre/post hash of every
mutated file, printed at the end of this document.


## Pre-run file hashes

```
  456c553ccbc6e739c3a23135e05950af02dd462c6e2cf5c4546f212e4138af0f  crates/state/src/healthcare_view.rs
  4cfefc3b35701dcba65015f1e76aa1bbb328ff143052e87d94eee7d2063f211c  crates/state/src/healthcare_executor.rs
  be244b8dd8e3bac70570cd6f3f2bafb93211eace6842816f838e204cd608bb3d  crates/state/src/executor.rs
  86fa1c1e2e852d1a805d74e9246371971f3f9fac35e2cd478b9f2c6d7a1db928  crates/storage/src/healthcare_store.rs
```


## The 116 mutations


### `crates/state/src/healthcare_view.rs`


#### A1 v_get_provider sees nothing

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_membership_finds_a_provider_registered_earlier_in_the_same_block` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `710b15fe531ae991` -> replacement `496ea388c223ef1a`
* verdict: **KILLED**

Anchor:
```rust
match view
            .get(cf::HEALTHCARE_PROVIDERS, provider_key(provider_id))
            .map_err(StateError::Storage)?
        {
```
Replacement:
```rust
match None::<Vec<u8>> {
```
Printed by libtest while mutated:
```
test a_membership_finds_a_provider_registered_earlier_in_the_same_block ... FAILED
```

#### A2 v_get_membership sees nothing

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_membership_is_suspended_and_reinstated_within_one_block` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `82a231680f9251bc` -> replacement `496ea388c223ef1a`
* verdict: **KILLED**

Anchor:
```rust
match view
            .get(cf::HEALTHCARE_MEMBERSHIPS, membership_key(membership_id))
            .map_err(StateError::Storage)?
        {
```
Replacement:
```rust
match None::<Vec<u8>> {
```
Printed by libtest while mutated:
```
test a_membership_is_suspended_and_reinstated_within_one_block ... FAILED
```

#### A3 v_get_consent sees nothing

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_consent_is_granted_and_superseded_within_one_block` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `21a076d68cd5c474` -> replacement `496ea388c223ef1a`
* verdict: **KILLED**

Anchor:
```rust
match view
            .get(cf::HEALTHCARE_CONSENTS, consent_key(consent_id))
            .map_err(StateError::Storage)?
        {
```
Replacement:
```rust
match None::<Vec<u8>> {
```
Printed by libtest while mutated:
```
test a_consent_is_granted_and_superseded_within_one_block ... FAILED
```

#### A4 v_get_prescription sees nothing

* occurrences checked before applying: **1** (expected 1)
* covering test: `one_partial_fill_records_exactly_one` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `d5753b7a8ca8ff35` -> replacement `496ea388c223ef1a`
* verdict: **KILLED**

Anchor:
```rust
match view
            .get(
                cf::HEALTHCARE_PRESCRIPTIONS,
                prescription_key(prescription_id),
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
test one_partial_fill_records_exactly_one ... FAILED
```

#### A5 v_get_network_provider_ids sees nothing

* occurrences checked before applying: **1** (expected 1)
* covering test: `two_providers_for_one_plan_accumulate_in_the_network_index` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `348bd785724dd6b1` -> replacement `496ea388c223ef1a`
* verdict: **KILLED**

Anchor:
```rust
match view
            .get(
                cf::HEALTHCARE_PROVIDER_NETWORK_INDEX,
                provider_network_index_key(plan_id),
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
test two_providers_for_one_plan_accumulate_in_the_network_index ... FAILED
```

#### A6 v_get_member_membership_ids sees nothing

* occurrences checked before applying: **1** (expected 1)
* covering test: `two_memberships_for_one_member_accumulate_in_the_index` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `4cd66c82681173f5` -> replacement `496ea388c223ef1a`
* verdict: **KILLED**

Anchor:
```rust
match view
            .get(
                cf::HEALTHCARE_MEMBER_INDEX,
                member_index_key(member_nullifier),
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
test two_memberships_for_one_member_accumulate_in_the_index ... FAILED
```

#### A7 v_get_subject_consent_ids sees nothing

* occurrences checked before applying: **1** (expected 1)
* covering test: `two_consents_for_one_subject_accumulate_in_the_index` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `6216e0bcf5402069` -> replacement `496ea388c223ef1a`
* verdict: **KILLED**

Anchor:
```rust
match view
            .get(
                cf::HEALTHCARE_SUBJECT_CONSENT_INDEX,
                subject_consent_index_key(subject_nullifier),
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
test two_consents_for_one_subject_accumulate_in_the_index ... FAILED
```

#### A8 v_get_patient_rx_ids sees nothing

* occurrences checked before applying: **1** (expected 1)
* covering test: `two_prescriptions_accumulate_in_both_indexes` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `22a7f3cfe72cb83b` -> replacement `496ea388c223ef1a`
* verdict: **KILLED**

Anchor:
```rust
match view
            .get(
                cf::HEALTHCARE_PATIENT_RX_INDEX,
                patient_rx_index_key(patient_nullifier),
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
test two_prescriptions_accumulate_in_both_indexes ... FAILED
```

#### A9 v_get_prescriber_rx_ids sees nothing

* occurrences checked before applying: **1** (expected 1)
* covering test: `two_prescriptions_accumulate_in_both_indexes` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `8eda9d8d797652f2` -> replacement `496ea388c223ef1a`
* verdict: **KILLED**

Anchor:
```rust
match view
            .get(
                cf::HEALTHCARE_PRESCRIBER_RX_INDEX,
                prescriber_rx_index_key(prescriber_id),
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
test two_prescriptions_accumulate_in_both_indexes ... FAILED
```

#### B1 v_provider_exists always says no

* occurrences checked before applying: **1** (expected 1)
* covering test: `every_duplicate_id_guard_reads_the_candidate` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `c61871256b0c5ddd` -> replacement `a86fd8bc70cf8c3e`
* verdict: **KILLED**

Anchor:
```rust
view.contains(cf::HEALTHCARE_PROVIDERS, provider_key(provider_id))
            .map_err(StateError::Storage)
```
Replacement:
```rust
Ok(false)
```
Printed by libtest while mutated:
```
test every_duplicate_id_guard_reads_the_candidate ... FAILED
```

#### B2 v_membership_exists always says no

* occurrences checked before applying: **1** (expected 1)
* covering test: `every_duplicate_id_guard_reads_the_candidate` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `45028802a1312d17` -> replacement `a86fd8bc70cf8c3e`
* verdict: **KILLED**

Anchor:
```rust
view.contains(cf::HEALTHCARE_MEMBERSHIPS, membership_key(membership_id))
            .map_err(StateError::Storage)
```
Replacement:
```rust
Ok(false)
```
Printed by libtest while mutated:
```
test every_duplicate_id_guard_reads_the_candidate ... FAILED
```

#### B3 v_consent_exists always says no

* occurrences checked before applying: **1** (expected 1)
* covering test: `every_duplicate_id_guard_reads_the_candidate` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `67bf420ec3e87186` -> replacement `a86fd8bc70cf8c3e`
* verdict: **KILLED**

Anchor:
```rust
view.contains(cf::HEALTHCARE_CONSENTS, consent_key(consent_id))
            .map_err(StateError::Storage)
```
Replacement:
```rust
Ok(false)
```
Printed by libtest while mutated:
```
test every_duplicate_id_guard_reads_the_candidate ... FAILED
```

#### B4 v_prescription_exists always says no

* occurrences checked before applying: **1** (expected 1)
* covering test: `every_duplicate_id_guard_reads_the_candidate` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `af7927cc64a0fd4f` -> replacement `a86fd8bc70cf8c3e`
* verdict: **KILLED**

Anchor:
```rust
view.contains(
            cf::HEALTHCARE_PRESCRIPTIONS,
            prescription_key(prescription_id),
        )
        .map_err(StateError::Storage)
```
Replacement:
```rust
Ok(false)
```
Printed by libtest while mutated:
```
test every_duplicate_id_guard_reads_the_candidate ... FAILED
```

#### B5 v_healthcare_proof_exists always says no

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_corrupt_proof_row_is_read_as_presence_not_as_corruption` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `17c3cdeec5ae8e82` -> replacement `a86fd8bc70cf8c3e`
* verdict: **KILLED**

Anchor:
```rust
view.contains(cf::HEALTHCARE_PROOFS, healthcare_proof_key(proof_id))
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

#### C1 provider row not staged

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_membership_finds_a_provider_registered_earlier_in_the_same_block` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `98725e086dfd3925` -> replacement `e7d8ee9a647bdb21`
* verdict: **KILLED**

Anchor:
```rust
view.put(
            cf::HEALTHCARE_PROVIDERS,
            provider_key(&provider.provider_id),
            &bytes,
        )
        .map_err(StateError::Storage)
```
Replacement:
```rust
Ok::<(), StateError>(())
```
Printed by libtest while mutated:
```
test a_membership_finds_a_provider_registered_earlier_in_the_same_block ... FAILED
```

#### C2 provider network-index loop skipped

* occurrences checked before applying: **1** (expected 1)
* covering test: `two_providers_for_one_plan_accumulate_in_the_network_index` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `15c805c4cabc8aff` -> replacement `e3b0c44298fc1c14`
* verdict: **KILLED**

Anchor:
```rust
        for plan_id in &provider.network_affiliations {
            Self::v_add_to_network_index(view, &provider.provider_id, plan_id)?;
        }
```
Replacement:
```rust
(deleted)
```
Printed by libtest while mutated:
```
test two_providers_for_one_plan_accumulate_in_the_network_index ... FAILED
```

#### C3 network-index append not staged

* occurrences checked before applying: **1** (expected 1)
* covering test: `two_providers_for_one_plan_accumulate_in_the_network_index` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `c06f3a0196d7276f` -> replacement `b74daaa82fe8579d`
* verdict: **KILLED**

Anchor:
```rust
        ids.push(*provider_id);
        let bytes = encode_provider_ids(&ids).map_err(StateError::Storage)?;
        view.put(
            cf::HEALTHCARE_PROVIDER_NETWORK_INDEX,
            provider_network_index_key(plan_id),
            &bytes,
        )
        .map_err(StateError::Storage)
```
Replacement:
```rust
        ids.push(*provider_id);
        let bytes = encode_provider_ids(&ids).map_err(StateError::Storage)?;
        Ok(())
```
Printed by libtest while mutated:
```
test two_providers_for_one_plan_accumulate_in_the_network_index ... FAILED
```

#### C4 network-index removal not staged

* occurrences checked before applying: **1** (expected 1)
* covering test: `an_affiliation_added_twice_in_one_block_lands_once` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `c05aa5d06174b7fc` -> replacement `f1965cbd2c983a91`
* verdict: **KILLED**

Anchor:
```rust
        ids.retain(|id| id != provider_id);
        let bytes = encode_provider_ids(&ids).map_err(StateError::Storage)?;
        view.put(
            cf::HEALTHCARE_PROVIDER_NETWORK_INDEX,
            provider_network_index_key(plan_id),
            &bytes,
        )
        .map_err(StateError::Storage)
```
Replacement:
```rust
        ids.retain(|id| id != provider_id);
        let bytes = encode_provider_ids(&ids).map_err(StateError::Storage)?;
        Ok(())
```
Printed by libtest while mutated:
```
test an_affiliation_added_twice_in_one_block_lands_once ... FAILED
```

#### C5 provider status write not staged

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_provider_is_suspended_and_reactivated_within_one_block` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `2fa76ea13a0b2ab5` -> replacement `4fdbb5d258603756`
* verdict: **KILLED**

Anchor:
```rust
                provider.status = status;
                provider.updated_at = timestamp;
                let bytes = encode_provider(&provider).map_err(StateError::Storage)?;
                view.put(cf::HEALTHCARE_PROVIDERS, provider_key(provider_id), &bytes)
                    .map_err(StateError::Storage)
```
Replacement:
```rust
                provider.status = status;
                provider.updated_at = timestamp;
                let bytes = encode_provider(&provider).map_err(StateError::Storage)?;
                Ok(())
```
Printed by libtest while mutated:
```
test a_provider_is_suspended_and_reactivated_within_one_block ... FAILED
```

#### C6 affiliation add does not rewrite the provider

* occurrences checked before applying: **1** (expected 1)
* covering test: `an_affiliation_added_twice_in_one_block_lands_once` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `4473bd41c0959b1c` -> replacement `e7d8ee9a647bdb21`
* verdict: **KILLED**

Anchor:
```rust
view.put(cf::HEALTHCARE_PROVIDERS, provider_key(provider_id), &bytes)
                        .map_err(StateError::Storage)
```
Replacement:
```rust
Ok::<(), StateError>(())
```
Printed by libtest while mutated:
```
test an_affiliation_added_twice_in_one_block_lands_once ... FAILED
```

#### C7 affiliation remove does not rewrite the provider

* occurrences checked before applying: **1** (expected 1)
* covering test: `an_affiliation_added_twice_in_one_block_lands_once` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `769bdd63f2bc04c5` -> replacement `abbe57b656c29938`
* verdict: **KILLED**

Anchor:
```rust
                provider.network_affiliations.retain(|p| p != plan_id);
                provider.updated_at = timestamp;
                let bytes = encode_provider(&provider).map_err(StateError::Storage)?;
                view.put(cf::HEALTHCARE_PROVIDERS, provider_key(provider_id), &bytes)
                    .map_err(StateError::Storage)
```
Replacement:
```rust
                provider.network_affiliations.retain(|p| p != plan_id);
                provider.updated_at = timestamp;
                let bytes = encode_provider(&provider).map_err(StateError::Storage)?;
                Ok::<(), StateError>(())
```
Printed by libtest while mutated:
```
test an_affiliation_added_twice_in_one_block_lands_once ... FAILED
```

#### C8 membership row not staged

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_membership_is_suspended_and_reinstated_within_one_block` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `68aa8f16f79b7a51` -> replacement `e7d8ee9a647bdb21`
* verdict: **KILLED**

Anchor:
```rust
view.put(
            cf::HEALTHCARE_MEMBERSHIPS,
            membership_key(&membership.membership_id),
            &bytes,
        )
        .map_err(StateError::Storage)
```
Replacement:
```rust
Ok::<(), StateError>(())
```
Printed by libtest while mutated:
```
test a_membership_is_suspended_and_reinstated_within_one_block ... FAILED
```

#### C9 membership member-index call skipped

* occurrences checked before applying: **1** (expected 1)
* covering test: `two_memberships_for_one_member_accumulate_in_the_index` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `62e1f0cce63935e0` -> replacement `b17e351a96d51a7c`
* verdict: **KILLED**

Anchor:
```rust
        Self::v_add_to_member_index(
            view,
            &membership.member_nullifier,
            &membership.membership_id,
        )
```
Replacement:
```rust
        Ok(())
```
Printed by libtest while mutated:
```
test two_memberships_for_one_member_accumulate_in_the_index ... FAILED
```

#### C10 member-index append not staged

* occurrences checked before applying: **1** (expected 1)
* covering test: `two_memberships_for_one_member_accumulate_in_the_index` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `2fa400f457d2b919` -> replacement `b32551e9b7f4fc6f`
* verdict: **KILLED**

Anchor:
```rust
view.put(
            cf::HEALTHCARE_MEMBER_INDEX,
            member_index_key(member_nullifier),
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
test two_memberships_for_one_member_accumulate_in_the_index ... FAILED
```

#### C11 membership status write not staged

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_membership_is_suspended_and_reinstated_within_one_block` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `0d3f1816f9a8d19d` -> replacement `bcc04a5c250c5b93`
* verdict: **KILLED**

Anchor:
```rust
                membership.status = status;
                membership.updated_at = timestamp;
                let bytes = encode_membership(&membership).map_err(StateError::Storage)?;
                view.put(
                    cf::HEALTHCARE_MEMBERSHIPS,
                    membership_key(membership_id),
                    &bytes,
                )
                .map_err(StateError::Storage)
```
Replacement:
```rust
                membership.status = status;
                membership.updated_at = timestamp;
                let bytes = encode_membership(&membership).map_err(StateError::Storage)?;
                Ok(())
```
Printed by libtest while mutated:
```
test a_membership_is_suspended_and_reinstated_within_one_block ... FAILED
```

#### C12 renewal not staged

* occurrences checked before applying: **1** (expected 1)
* covering test: `renewing_a_terminated_membership_makes_it_active_again` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `6d24654c3a6b32f9` -> replacement `a119f023bcd1fab3`
* verdict: **KILLED**

Anchor:
```rust
                membership.status = MembershipStatus::Active;
                membership.updated_at = timestamp;
                let bytes = encode_membership(&membership).map_err(StateError::Storage)?;
                view.put(
                    cf::HEALTHCARE_MEMBERSHIPS,
                    membership_key(membership_id),
                    &bytes,
                )
                .map_err(StateError::Storage)
```
Replacement:
```rust
                membership.status = MembershipStatus::Active;
                membership.updated_at = timestamp;
                let bytes = encode_membership(&membership).map_err(StateError::Storage)?;
                Ok(())
```
Printed by libtest while mutated:
```
test renewing_a_terminated_membership_makes_it_active_again ... FAILED
```

#### C13 dependent add not staged

* occurrences checked before applying: **1** (expected 1)
* covering test: `dependents_added_in_one_block_accumulate_and_deduplicate` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `81ccc73a97dcc1e4` -> replacement `e7d8ee9a647bdb21`
* verdict: **KILLED**

Anchor:
```rust
view.put(
                        cf::HEALTHCARE_MEMBERSHIPS,
                        membership_key(membership_id),
                        &bytes,
                    )
                    .map_err(StateError::Storage)
```
Replacement:
```rust
Ok::<(), StateError>(())
```
Printed by libtest while mutated:
```
test dependents_added_in_one_block_accumulate_and_deduplicate ... FAILED
```

#### C14 dependent remove not staged

* occurrences checked before applying: **1** (expected 1)
* covering test: `dependents_added_in_one_block_accumulate_and_deduplicate` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `25e7d41c3468a1cd` -> replacement `c459aa200c90fd35`
* verdict: **KILLED**

Anchor:
```rust
                membership.dependents.retain(|d| d != dependent_commitment);
                membership.updated_at = timestamp;
                let bytes = encode_membership(&membership).map_err(StateError::Storage)?;
                view.put(
                    cf::HEALTHCARE_MEMBERSHIPS,
                    membership_key(membership_id),
                    &bytes,
                )
                .map_err(StateError::Storage)
```
Replacement:
```rust
                membership.dependents.retain(|d| d != dependent_commitment);
                membership.updated_at = timestamp;
                let bytes = encode_membership(&membership).map_err(StateError::Storage)?;
                Ok(())
```
Printed by libtest while mutated:
```
test dependents_added_in_one_block_accumulate_and_deduplicate ... FAILED
```

#### C15 consent row not staged

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_consent_is_granted_and_superseded_within_one_block` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `a1c8ffb43544959a` -> replacement `e7d8ee9a647bdb21`
* verdict: **KILLED**

Anchor:
```rust
view.put(
            cf::HEALTHCARE_CONSENTS,
            consent_key(&consent.consent_id),
            &bytes,
        )
        .map_err(StateError::Storage)
```
Replacement:
```rust
Ok::<(), StateError>(())
```
Printed by libtest while mutated:
```
test a_consent_is_granted_and_superseded_within_one_block ... FAILED
```

#### C16 consent subject-index call skipped

* occurrences checked before applying: **1** (expected 1)
* covering test: `two_consents_for_one_subject_accumulate_in_the_index` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `b3373594e111d8de` -> replacement `b17e351a96d51a7c`
* verdict: **KILLED**

Anchor:
```rust
        Self::v_add_to_subject_index(view, &consent.subject_nullifier, &consent.consent_id)
```
Replacement:
```rust
        Ok(())
```
Printed by libtest while mutated:
```
test two_consents_for_one_subject_accumulate_in_the_index ... FAILED
```

#### C17 subject-index append not staged

* occurrences checked before applying: **1** (expected 1)
* covering test: `two_consents_for_one_subject_accumulate_in_the_index` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `4e5dfaa472bf3042` -> replacement `b32551e9b7f4fc6f`
* verdict: **KILLED**

Anchor:
```rust
view.put(
            cf::HEALTHCARE_SUBJECT_CONSENT_INDEX,
            subject_consent_index_key(subject_nullifier),
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
test two_consents_for_one_subject_accumulate_in_the_index ... FAILED
```

#### C18 consent status write not staged

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_consent_is_granted_and_superseded_within_one_block` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `ccd4e4dfd1492189` -> replacement `b32551e9b7f4fc6f`
* verdict: **KILLED**

Anchor:
```rust
view.put(cf::HEALTHCARE_CONSENTS, consent_key(consent_id), &bytes)
                    .map_err(StateError::Storage)
```
Replacement:
```rust
Ok(())
```
Printed by libtest while mutated:
```
test a_consent_is_granted_and_superseded_within_one_block ... FAILED
```

#### C19 prescription row not staged

* occurrences checked before applying: **1** (expected 1)
* covering test: `one_partial_fill_records_exactly_one` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `11c282ead3e0799c` -> replacement `e7d8ee9a647bdb21`
* verdict: **KILLED**

Anchor:
```rust
view.put(
            cf::HEALTHCARE_PRESCRIPTIONS,
            prescription_key(&prescription.prescription_id),
            &bytes,
        )
        .map_err(StateError::Storage)
```
Replacement:
```rust
Ok::<(), StateError>(())
```
Printed by libtest while mutated:
```
test one_partial_fill_records_exactly_one ... FAILED
```

#### C20 prescription patient-index call skipped

* occurrences checked before applying: **1** (expected 1)
* covering test: `two_prescriptions_accumulate_in_both_indexes` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `7b1506521a2907ae` -> replacement `e3b0c44298fc1c14`
* verdict: **KILLED**

Anchor:
```rust
        Self::v_add_to_patient_index(
            view,
            &prescription.patient_nullifier,
            &prescription.prescription_id,
        )?;
```
Replacement:
```rust
(deleted)
```
Printed by libtest while mutated:
```
test two_prescriptions_accumulate_in_both_indexes ... FAILED
```

#### C21 prescription prescriber-index call skipped

* occurrences checked before applying: **1** (expected 1)
* covering test: `two_prescriptions_accumulate_in_both_indexes` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `d74c27ff92dcafb1` -> replacement `b17e351a96d51a7c`
* verdict: **KILLED**

Anchor:
```rust
        Self::v_add_to_prescriber_index(
            view,
            &prescription.prescriber_provider_id,
            &prescription.prescription_id,
        )
```
Replacement:
```rust
        Ok(())
```
Printed by libtest while mutated:
```
test two_prescriptions_accumulate_in_both_indexes ... FAILED
```

#### C22 patient-index append not staged

* occurrences checked before applying: **1** (expected 1)
* covering test: `two_prescriptions_accumulate_in_both_indexes` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `157d5c7c02ea6c18` -> replacement `b32551e9b7f4fc6f`
* verdict: **KILLED**

Anchor:
```rust
view.put(
            cf::HEALTHCARE_PATIENT_RX_INDEX,
            patient_rx_index_key(patient_nullifier),
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
test two_prescriptions_accumulate_in_both_indexes ... FAILED
```

#### C23 prescriber-index append not staged

* occurrences checked before applying: **1** (expected 1)
* covering test: `two_prescriptions_accumulate_in_both_indexes` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `c19f89e514949a8f` -> replacement `b32551e9b7f4fc6f`
* verdict: **KILLED**

Anchor:
```rust
view.put(
            cf::HEALTHCARE_PRESCRIBER_RX_INDEX,
            prescriber_rx_index_key(prescriber_id),
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
test two_prescriptions_accumulate_in_both_indexes ... FAILED
```

#### C24 prescription status write not staged

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_prescription_is_held_and_released_within_one_block` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `8f49f209cb420596` -> replacement `545400a41a6b9d21`
* verdict: **KILLED**

Anchor:
```rust
                prescription.status = status;
                prescription.updated_at = timestamp;
                let bytes = encode_prescription(&prescription).map_err(StateError::Storage)?;
                view.put(
                    cf::HEALTHCARE_PRESCRIPTIONS,
                    prescription_key(prescription_id),
                    &bytes,
                )
                .map_err(StateError::Storage)
```
Replacement:
```rust
                prescription.status = status;
                prescription.updated_at = timestamp;
                let bytes = encode_prescription(&prescription).map_err(StateError::Storage)?;
                Ok(())
```
Printed by libtest while mutated:
```
test a_prescription_is_held_and_released_within_one_block ... FAILED
```

#### C25 fill not staged

* occurrences checked before applying: **1** (expected 1)
* covering test: `two_fills_in_one_block_decrement_refills_twice` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `4205a4d2be3c381d` -> replacement `cd9d84acd836e4b6`
* verdict: **KILLED**

Anchor:
```rust
                };
                prescription.updated_at = timestamp;
                let bytes = encode_prescription(&prescription).map_err(StateError::Storage)?;
                view.put(
                    cf::HEALTHCARE_PRESCRIPTIONS,
                    prescription_key(prescription_id),
                    &bytes,
                )
                .map_err(StateError::Storage)
```
Replacement:
```rust
                };
                prescription.updated_at = timestamp;
                let bytes = encode_prescription(&prescription).map_err(StateError::Storage)?;
                Ok(())
```
Printed by libtest while mutated:
```
test two_fills_in_one_block_decrement_refills_twice ... FAILED
```

#### C26 fill-history append not staged

* occurrences checked before applying: **1** (expected 1)
* covering test: `one_partial_fill_records_exactly_one` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `57be17ed1282a965` -> replacement `af43e0ab392f8880`
* verdict: **KILLED**

Anchor:
```rust
                prescription.fill_history.push(fill_commitment);
                prescription.updated_at = timestamp;
                let bytes = encode_prescription(&prescription).map_err(StateError::Storage)?;
                view.put(
                    cf::HEALTHCARE_PRESCRIPTIONS,
                    prescription_key(prescription_id),
                    &bytes,
                )
                .map_err(StateError::Storage)
```
Replacement:
```rust
                prescription.fill_history.push(fill_commitment);
                prescription.updated_at = timestamp;
                let bytes = encode_prescription(&prescription).map_err(StateError::Storage)?;
                Ok(())
```
Printed by libtest while mutated:
```
test one_partial_fill_records_exactly_one ... FAILED
```

#### C27 proof not staged

* occurrences checked before applying: **1** (expected 1)
* covering test: `every_duplicate_id_guard_reads_the_candidate` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `69e46cf1469b88f6` -> replacement `b32551e9b7f4fc6f`
* verdict: **KILLED**

Anchor:
```rust
view.put(
            cf::HEALTHCARE_PROOFS,
            healthcare_proof_key(&proof.proof_id),
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
test every_duplicate_id_guard_reads_the_candidate ... FAILED
```

#### D1 v_get_provider reads corruption as absence

* occurrences checked before applying: **1** (expected 1)
* covering test: `corrupt_rows_error_through_dispatch_with_exactly_this_staged` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `b7d1944ab9db3771` -> replacement `e4aff03ada9f09d7`
* verdict: **KILLED**

Anchor:
```rust
Ok(Some(decode_provider(&bytes).map_err(StateError::Storage)?))
```
Replacement:
```rust
Ok(decode_provider(&bytes).ok())
```
Printed by libtest while mutated:
```
test corrupt_rows_error_through_dispatch_with_exactly_this_staged ... FAILED
```

#### D3 v_get_consent reads corruption as absence

* occurrences checked before applying: **1** (expected 1)
* covering test: `corrupt_rows_error_through_dispatch_with_exactly_this_staged` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `7d6bc14cbbcee1b7` -> replacement `56534e5dc15be160`
* verdict: **KILLED**

Anchor:
```rust
Ok(Some(decode_consent(&bytes).map_err(StateError::Storage)?))
```
Replacement:
```rust
Ok(decode_consent(&bytes).ok())
```
Printed by libtest while mutated:
```
test corrupt_rows_error_through_dispatch_with_exactly_this_staged ... FAILED
```

#### D2 v_get_membership reads corruption as absence

* occurrences checked before applying: **1** (expected 1)
* covering test: `corrupt_rows_error_through_dispatch_with_exactly_this_staged` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `a0032eae1746c396` -> replacement `c26392cc2fad76f2`
* verdict: **KILLED**

Anchor:
```rust
Ok(Some(
                decode_membership(&bytes).map_err(StateError::Storage)?,
            ))
```
Replacement:
```rust
Ok(decode_membership(&bytes).ok())
```
Printed by libtest while mutated:
```
test corrupt_rows_error_through_dispatch_with_exactly_this_staged ... FAILED
```

#### D4 v_get_prescription reads corruption as absence

* occurrences checked before applying: **1** (expected 1)
* covering test: `corrupt_rows_error_through_dispatch_with_exactly_this_staged` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `565a854f50e99da6` -> replacement `532f8a0e9949ca1c`
* verdict: **KILLED**

Anchor:
```rust
Ok(Some(
                decode_prescription(&bytes).map_err(StateError::Storage)?,
            ))
```
Replacement:
```rust
Ok(decode_prescription(&bytes).ok())
```
Printed by libtest while mutated:
```
test corrupt_rows_error_through_dispatch_with_exactly_this_staged ... FAILED
```

#### D5 v_get_network_provider_ids reads a corrupt list as empty

* occurrences checked before applying: **1** (expected 1)
* covering test: `corrupt_rows_error_through_dispatch_with_exactly_this_staged` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `fe09f5c568cb4ac9` -> replacement `18a86f03be7b9d92`
* verdict: **KILLED**

Anchor:
```rust
Some(bytes) => decode_provider_ids(&bytes).map_err(StateError::Storage),
```
Replacement:
```rust
Some(bytes) => Ok(decode_provider_ids(&bytes).unwrap_or_default()),
```
Printed by libtest while mutated:
```
test corrupt_rows_error_through_dispatch_with_exactly_this_staged ... FAILED
```

#### D6 v_get_member_membership_ids reads a corrupt list as empty

* occurrences checked before applying: **1** (expected 1)
* covering test: `corrupt_rows_error_through_dispatch_with_exactly_this_staged` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `d942afd41ceb23ad` -> replacement `75c8003dfbf206bd`
* verdict: **KILLED**

Anchor:
```rust
Some(bytes) => decode_membership_ids(&bytes).map_err(StateError::Storage),
```
Replacement:
```rust
Some(bytes) => Ok(decode_membership_ids(&bytes).unwrap_or_default()),
```
Printed by libtest while mutated:
```
test corrupt_rows_error_through_dispatch_with_exactly_this_staged ... FAILED
```

#### D7 v_get_subject_consent_ids reads a corrupt list as empty

* occurrences checked before applying: **1** (expected 1)
* covering test: `corrupt_rows_error_through_dispatch_with_exactly_this_staged` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `fd94311501652e58` -> replacement `b8cfbd993cee79e0`
* verdict: **KILLED**

Anchor:
```rust
Some(bytes) => decode_consent_ids(&bytes).map_err(StateError::Storage),
```
Replacement:
```rust
Some(bytes) => Ok(decode_consent_ids(&bytes).unwrap_or_default()),
```
Printed by libtest while mutated:
```
test corrupt_rows_error_through_dispatch_with_exactly_this_staged ... FAILED
```

#### D8 v_get_patient_rx_ids reads a corrupt list as empty

* occurrences checked before applying: **1** (expected 1)
* covering test: `corrupt_rows_error_through_dispatch_with_exactly_this_staged` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `55eafa831ce7b84e` -> replacement `10141be330c85914`
* verdict: **KILLED**

Anchor:
```rust
                patient_rx_index_key(patient_nullifier),
            )
            .map_err(StateError::Storage)?
        {
            Some(bytes) => decode_prescription_ids(&bytes).map_err(StateError::Storage),
```
Replacement:
```rust
                patient_rx_index_key(patient_nullifier),
            )
            .map_err(StateError::Storage)?
        {
            Some(bytes) => Ok(decode_prescription_ids(&bytes).unwrap_or_default()),
```
Printed by libtest while mutated:
```
test corrupt_rows_error_through_dispatch_with_exactly_this_staged ... FAILED
```

#### D9 v_get_prescriber_rx_ids reads a corrupt list as empty

* occurrences checked before applying: **1** (expected 1)
* covering test: `corrupt_rows_error_through_dispatch_with_exactly_this_staged` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `85722b24efef08ef` -> replacement `f8f8958349b1097b`
* verdict: **KILLED**

Anchor:
```rust
                prescriber_rx_index_key(prescriber_id),
            )
            .map_err(StateError::Storage)?
        {
            Some(bytes) => decode_prescription_ids(&bytes).map_err(StateError::Storage),
```
Replacement:
```rust
                prescriber_rx_index_key(prescriber_id),
            )
            .map_err(StateError::Storage)?
        {
            Some(bytes) => Ok(decode_prescription_ids(&bytes).unwrap_or_default()),
```
Printed by libtest while mutated:
```
test corrupt_rows_error_through_dispatch_with_exactly_this_staged ... FAILED
```

#### E1 provider index appended BEFORE the provider row

* occurrences checked before applying: **1** (expected 1)
* covering test: `corrupt_rows_error_through_dispatch_with_exactly_this_staged` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `a8b9cd801c7b4dbc` -> replacement `9899810245d687fc`
* verdict: **KILLED**

Anchor:
```rust
view.put(
            cf::HEALTHCARE_PROVIDERS,
            provider_key(&provider.provider_id),
            &bytes,
        )
        .map_err(StateError::Storage)?;
        for plan_id in &provider.network_affiliations {
            Self::v_add_to_network_index(view, &provider.provider_id, plan_id)?;
        }
        Ok(())
```
Replacement:
```rust
for plan_id in &provider.network_affiliations {
            Self::v_add_to_network_index(view, &provider.provider_id, plan_id)?;
        }
        view.put(
            cf::HEALTHCARE_PROVIDERS,
            provider_key(&provider.provider_id),
            &bytes,
        )
        .map_err(StateError::Storage)?;
        Ok(())
```
Printed by libtest while mutated:
```
test corrupt_rows_error_through_dispatch_with_exactly_this_staged ... FAILED
```

#### E2 member index appended BEFORE the membership row

* occurrences checked before applying: **1** (expected 1)
* covering test: `corrupt_rows_error_through_dispatch_with_exactly_this_staged` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `3648e87c44978906` -> replacement `be5786cc1aefb82b`
* verdict: **KILLED**

Anchor:
```rust
view.put(
            cf::HEALTHCARE_MEMBERSHIPS,
            membership_key(&membership.membership_id),
            &bytes,
        )
        .map_err(StateError::Storage)?;
        Self::v_add_to_member_index(
            view,
            &membership.member_nullifier,
            &membership.membership_id,
        )
```
Replacement:
```rust
        Self::v_add_to_member_index(
            view,
            &membership.member_nullifier,
            &membership.membership_id,
        )?;
        view.put(
            cf::HEALTHCARE_MEMBERSHIPS,
            membership_key(&membership.membership_id),
            &bytes,
        )
        .map_err(StateError::Storage)
```
Printed by libtest while mutated:
```
test corrupt_rows_error_through_dispatch_with_exactly_this_staged ... FAILED
```

#### E3 subject index appended BEFORE the consent row

* occurrences checked before applying: **1** (expected 1)
* covering test: `corrupt_rows_error_through_dispatch_with_exactly_this_staged` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `432cda41388000c3` -> replacement `98379d36ef2af8c6`
* verdict: **KILLED**

Anchor:
```rust
view.put(
            cf::HEALTHCARE_CONSENTS,
            consent_key(&consent.consent_id),
            &bytes,
        )
        .map_err(StateError::Storage)?;
        Self::v_add_to_subject_index(view, &consent.subject_nullifier, &consent.consent_id)
```
Replacement:
```rust
        Self::v_add_to_subject_index(view, &consent.subject_nullifier, &consent.consent_id)?;
        view.put(
            cf::HEALTHCARE_CONSENTS,
            consent_key(&consent.consent_id),
            &bytes,
        )
        .map_err(StateError::Storage)
```
Printed by libtest while mutated:
```
test corrupt_rows_error_through_dispatch_with_exactly_this_staged ... FAILED
```

#### E4 prescriber index appended BEFORE the patient index

* occurrences checked before applying: **1** (expected 1)
* covering test: `corrupt_rows_error_through_dispatch_with_exactly_this_staged` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `961a0b8408b2106e` -> replacement `172015a2cc25fd7a`
* verdict: **KILLED**

Anchor:
```rust
        Self::v_add_to_patient_index(
            view,
            &prescription.patient_nullifier,
            &prescription.prescription_id,
        )?;
        Self::v_add_to_prescriber_index(
            view,
            &prescription.prescriber_provider_id,
            &prescription.prescription_id,
        )
```
Replacement:
```rust
        Self::v_add_to_prescriber_index(
            view,
            &prescription.prescriber_provider_id,
            &prescription.prescription_id,
        )?;
        Self::v_add_to_patient_index(
            view,
            &prescription.patient_nullifier,
            &prescription.prescription_id,
        )
```
Printed by libtest while mutated:
```
test corrupt_rows_error_through_dispatch_with_exactly_this_staged ... FAILED
```

#### E5 fill status derived BEFORE the refill decrement

* occurrences checked before applying: **1** (expected 1)
* covering test: `the_fill_that_exhausts_refills_closes_the_prescription_within_the_block` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `657816cd5950229f` -> replacement `26879c8d568274d6`
* verdict: **KILLED**

Anchor:
```rust
                if prescription.refills_remaining > 0 {
                    prescription.refills_remaining =
                        prescription.refills_remaining.saturating_sub(1);
                }
                prescription.status = if prescription.refills_remaining == 0 {
                    PrescriptionStatus::Filled
                } else {
                    PrescriptionStatus::PartiallyFilled
                };
```
Replacement:
```rust
                prescription.status = if prescription.refills_remaining == 0 {
                    PrescriptionStatus::Filled
                } else {
                    PrescriptionStatus::PartiallyFilled
                };
                if prescription.refills_remaining > 0 {
                    prescription.refills_remaining =
                        prescription.refills_remaining.saturating_sub(1);
                }
```
Printed by libtest while mutated:
```
test the_fill_that_exhausts_refills_closes_the_prescription_within_the_block ... FAILED
```

#### G20 candidate network-index remove becomes conditional

* occurrences checked before applying: **1** (expected 1)
* covering test: `removing_an_affiliation_that_was_never_there_still_stages_an_empty_index` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `6800c1a1c9a9c891` -> replacement `0bab1cd2248f78a9`
* verdict: **KILLED**

Anchor:
```rust
        let mut ids = Self::v_get_network_provider_ids(view, plan_id)?;
        ids.retain(|id| id != provider_id);
```
Replacement:
```rust
        let mut ids = Self::v_get_network_provider_ids(view, plan_id)?;
        let before = ids.len();
        ids.retain(|id| id != provider_id);
        if ids.len() == before {
            return Ok(());
        }
```
Printed by libtest while mutated:
```
test removing_an_affiliation_that_was_never_there_still_stages_an_empty_index ... FAILED
```

#### I11 the proof guard decodes instead of probing for presence

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_corrupt_proof_row_is_read_as_presence_not_as_corruption` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `23b1090fd2738f26` -> replacement `de7859f2d925142a`
* verdict: **KILLED**

Anchor:
```rust
        view.contains(cf::HEALTHCARE_PROOFS, healthcare_proof_key(proof_id))
            .map_err(StateError::Storage)
```
Replacement:
```rust
        match view
            .get(cf::HEALTHCARE_PROOFS, healthcare_proof_key(proof_id))
            .map_err(StateError::Storage)?
        {
            Some(bytes) => {
                bincode::deserialize::<HealthcareProofEnvelope>(&bytes).map_err(|e| {
                    StateError::Storage(sumchain_storage::StorageError::Serialization(
                        e.to_string(),
                    ))
                })?;
                Ok(true)
            }
            None => Ok(false),
        }
```
Printed by libtest while mutated:
```
test a_corrupt_proof_row_is_read_as_presence_not_as_corruption ... FAILED
```

### `crates/state/src/healthcare_executor.rs`


#### H1 provider suspend issuer check removed

* occurrences checked before applying: **1** (expected 1)
* covering test: `any_sender_can_change_a_providers_network_affiliations` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `49b496ff0031e4c5` -> replacement `e3b0c44298fc1c14`
* verdict: **KILLED**

Anchor:
```rust
                if provider.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Only issuer can suspend"));
                }
```
Replacement:
```rust
(deleted)
```
Printed by libtest while mutated:
```
test any_sender_can_change_a_providers_network_affiliations ... FAILED
```

#### H2 consent revoke issuer check removed

* occurrences checked before applying: **1** (expected 1)
* covering test: `the_subject_of_a_consent_can_neither_grant_nor_revoke_it` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `578a742bd05c8ed6` -> replacement `e3b0c44298fc1c14`
* verdict: **KILLED**

Anchor:
```rust
                if consent.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Only issuer can revoke"));
                }
```
Replacement:
```rust
(deleted)
```
Printed by libtest while mutated:
```
test the_subject_of_a_consent_can_neither_grant_nor_revoke_it ... FAILED
```

#### H3 prescription cancel issuer check removed

* occurrences checked before applying: **1** (expected 1)
* covering test: `any_sender_can_fill_any_prescription` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `faf00e4b0d3084a2` -> replacement `e3b0c44298fc1c14`
* verdict: **KILLED**

Anchor:
```rust
                if prescription.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Only issuer can cancel"));
                }
```
Replacement:
```rust
(deleted)
```
Printed by libtest while mutated:
```
test any_sender_can_fill_any_prescription ... FAILED
```

#### H4 consent grant issuer check removed

* occurrences checked before applying: **1** (expected 1)
* covering test: `the_subject_of_a_consent_can_neither_grant_nor_revoke_it` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `4df9e1631ea7448c` -> replacement `e3b0c44298fc1c14`
* verdict: **KILLED**

Anchor:
```rust
                if consent.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Issuer must be sender"));
                }
```
Replacement:
```rust
(deleted)
```
Printed by libtest while mutated:
```
test the_subject_of_a_consent_can_neither_grant_nor_revoke_it ... FAILED
```

#### H5 provider reactivation status guard removed

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_provider_is_suspended_and_reactivated_within_one_block` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `dc65b5d473bcc7f5` -> replacement `e3b0c44298fc1c14`
* verdict: **KILLED**

Anchor:
```rust
                if provider.status != ProviderStatus::Suspended && provider.status != ProviderStatus::Inactive {
                    return Ok(HealthcareExecutionResult::failure("Provider is not suspended or inactive"));
                }
```
Replacement:
```rust
(deleted)
```
Printed by libtest while mutated:
```
test a_provider_is_suspended_and_reactivated_within_one_block ... FAILED
```

#### H6 membership reinstate status guard removed

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_membership_is_suspended_and_reinstated_within_one_block` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `a77ee9659401902a` -> replacement `e3b0c44298fc1c14`
* verdict: **KILLED**

Anchor:
```rust
                if membership.status != MembershipStatus::Suspended {
                    return Ok(HealthcareExecutionResult::failure("Membership is not suspended"));
                }
```
Replacement:
```rust
(deleted)
```
Printed by libtest while mutated:
```
test a_membership_is_suspended_and_reinstated_within_one_block ... FAILED
```

#### H7 prescription release-hold status guard removed

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_prescription_is_held_and_released_within_one_block` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `879f5a59aeadbb5b` -> replacement `e3b0c44298fc1c14`
* verdict: **KILLED**

Anchor:
```rust
                if prescription.status != PrescriptionStatus::OnHold {
                    return Ok(HealthcareExecutionResult::failure("Prescription is not on hold"));
                }
```
Replacement:
```rust
(deleted)
```
Printed by libtest while mutated:
```
test a_prescription_is_held_and_released_within_one_block ... FAILED
```

#### H8 membership provider-existence guard removed

* occurrences checked before applying: **1** (expected 1)
* covering test: `without_the_provider_the_same_membership_is_refused` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `b4d62a88afd1dcca` -> replacement `e3b0c44298fc1c14`
* verdict: **KILLED**

Anchor:
```rust
                if Self::v_get_provider(view, &membership.provider_id)?.is_none() {
                    return Ok(HealthcareExecutionResult::failure("Provider not found"));
                }
```
Replacement:
```rust
(deleted)
```
Printed by libtest while mutated:
```
test without_the_provider_the_same_membership_is_refused ... FAILED
```

#### H9 prescriber-existence guard removed

* occurrences checked before applying: **1** (expected 1)
* covering test: `without_the_prescriber_provider_the_same_prescription_is_refused` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `02fef71ae58baa19` -> replacement `e3b0c44298fc1c14`
* verdict: **KILLED**

Anchor:
```rust
                if Self::v_get_provider(view, &prescription.prescriber_provider_id)?.is_none() {
                    return Ok(HealthcareExecutionResult::failure("Prescriber provider not found"));
                }
```
Replacement:
```rust
(deleted)
```
Printed by libtest while mutated:
```
test without_the_prescriber_provider_the_same_prescription_is_refused ... FAILED
```

#### H10 old-consent guard removed from supersession

* occurrences checked before applying: **1** (expected 1)
* covering test: `without_the_old_consent_the_same_supersession_is_refused` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `53419c38673d3a0c` -> replacement `e3b0c44298fc1c14`
* verdict: **KILLED**

Anchor:
```rust
                if Self::v_get_consent(view, &d.old_consent_id)?.is_none() {
                    return Ok(HealthcareExecutionResult::failure("Old consent not found"));
                }
```
Replacement:
```rust
(deleted)
```
Printed by libtest while mutated:
```
test without_the_old_consent_the_same_supersession_is_refused ... FAILED
```

#### H11 fill validity guard removed

* occurrences checked before applying: **1** (expected 1)
* covering test: `the_block_timestamp_reaching_healthcare_operations_is_always_zero` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `f2d08fcd349a97a8` -> replacement `e3b0c44298fc1c14`
* verdict: **KILLED**

Anchor:
```rust
                if !prescription.is_valid(block_timestamp) {
                    return Ok(HealthcareExecutionResult::failure("Prescription is not valid"));
                }

                if prescription.refills_remaining == 0 && prescription.status != PrescriptionStatus::Active {
                    return Ok(HealthcareExecutionResult::failure("No fills remaining"));
                }
```
Replacement:
```rust
(deleted)
```
Printed by libtest while mutated:
```
test the_block_timestamp_reaching_healthcare_operations_is_always_zero ... FAILED
```

#### H12 controlled-substance guard removed

* occurrences checked before applying: **1** (expected 1)
* covering test: `the_controlled_substance_guard_covers_only_the_transfer_status` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `70b99c6737a82ec1` -> replacement `e3b0c44298fc1c14`
* verdict: **KILLED**

Anchor:
```rust
                // Prevent transfer of controlled substances
                if prescription.is_controlled && d.status == PrescriptionStatus::TransferRequested {
                    return Ok(HealthcareExecutionResult::failure(
                        "Controlled substance prescriptions cannot be transferred"
                    ));
                }
```
Replacement:
```rust
(deleted)
```
Printed by libtest while mutated:
```
test the_controlled_substance_guard_covers_only_the_transfer_status ... FAILED
```

#### I1 supersession gains an issuer check

* occurrences checked before applying: **1** (expected 1)
* covering test: `any_sender_can_supersede_any_consent_with_one_of_their_own` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `121429544a7e6dd6` -> replacement `436e836a46c9f641`
* verdict: **KILLED**

Anchor:
```rust
                if Self::v_get_consent(view, &d.old_consent_id)?.is_none() {
                    return Ok(HealthcareExecutionResult::failure("Old consent not found"));
                }

                StateManager::v_deduct(view, sender, fee)?;
```
Replacement:
```rust
                match Self::v_get_consent(view, &d.old_consent_id)? {
                    None => {
                        return Ok(HealthcareExecutionResult::failure("Old consent not found"));
                    }
                    Some(c) if c.issuer_address != *sender => {
                        return Ok(HealthcareExecutionResult::failure("Only issuer can supersede"));
                    }
                    Some(_) => {}
                }

                StateManager::v_deduct(view, sender, fee)?;
```
Printed by libtest while mutated:
```
test any_sender_can_supersede_any_consent_with_one_of_their_own ... FAILED
```

#### I2 fill gains an issuer check

* occurrences checked before applying: **1** (expected 1)
* covering test: `any_sender_can_fill_any_prescription` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `1c29a11183d01eaa` -> replacement `1b6bebb8cfadbd56`
* verdict: **KILLED**

Anchor:
```rust
                if prescription.refills_remaining == 0 && prescription.status != PrescriptionStatus::Active {
                    return Ok(HealthcareExecutionResult::failure("No fills remaining"));
                }
```
Replacement:
```rust
                if prescription.refills_remaining == 0 && prescription.status != PrescriptionStatus::Active {
                    return Ok(HealthcareExecutionResult::failure("No fills remaining"));
                }

                if prescription.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Only issuer can fill"));
                }
```
Printed by libtest while mutated:
```
test any_sender_can_fill_any_prescription ... FAILED
```

#### I3 partial fill gains an issuer check

* occurrences checked before applying: **1** (expected 1)
* covering test: `any_sender_can_fill_any_prescription` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `0b1973c45611de4b` -> replacement `120ccdfd898c3bea`
* verdict: **KILLED**

Anchor:
```rust
                StateManager::v_increment_nonce(view, sender)?;

                // Record partial fill (doesn't decrement refills)
```
Replacement:
```rust
                if prescription.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Only issuer can partial-fill"));
                }
                StateManager::v_increment_nonce(view, sender)?;

                // Record partial fill (doesn't decrement refills)
```
Printed by libtest while mutated:
```
test any_sender_can_fill_any_prescription ... FAILED
```

#### I4 affiliation add gains an issuer check

* occurrences checked before applying: **1** (expected 1)
* covering test: `any_sender_can_change_a_providers_network_affiliations` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `f48bd9752c9d1b57` -> replacement `73ad41d60733eb68`
* verdict: **KILLED**

Anchor:
```rust
                if Self::v_get_provider(view, &d.provider_id)?.is_none() {
                    return Ok(HealthcareExecutionResult::failure("Provider not found"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_add_network_affiliation(
```
Replacement:
```rust
                match Self::v_get_provider(view, &d.provider_id)? {
                    None => return Ok(HealthcareExecutionResult::failure("Provider not found")),
                    Some(p) if p.issuer_address != *sender => {
                        return Ok(HealthcareExecutionResult::failure("Only issuer can affiliate"));
                    }
                    Some(_) => {}
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_add_network_affiliation(
```
Printed by libtest while mutated:
```
test any_sender_can_change_a_providers_network_affiliations ... FAILED
```

#### I5 affiliation remove gains an issuer check

* occurrences checked before applying: **1** (expected 1)
* covering test: `any_sender_can_change_a_providers_network_affiliations` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `6216364fa411fdc4` -> replacement `a65c529c34374922`
* verdict: **KILLED**

Anchor:
```rust
                if Self::v_get_provider(view, &d.provider_id)?.is_none() {
                    return Ok(HealthcareExecutionResult::failure("Provider not found"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_remove_network_affiliation(
```
Replacement:
```rust
                match Self::v_get_provider(view, &d.provider_id)? {
                    None => return Ok(HealthcareExecutionResult::failure("Provider not found")),
                    Some(p) if p.issuer_address != *sender => {
                        return Ok(HealthcareExecutionResult::failure("Only issuer can disaffiliate"));
                    }
                    Some(_) => {}
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_remove_network_affiliation(
```
Printed by libtest while mutated:
```
test any_sender_can_change_a_providers_network_affiliations ... FAILED
```

#### I6 VerifyProof actually verifies

* occurrences checked before applying: **1** (expected 1)
* covering test: `verify_proof_succeeds_for_a_proof_that_does_not_exist` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `3a645f108381249c` -> replacement `2811a5e7efb38337`
* verdict: **KILLED**

Anchor:
```rust
            HealthcareOperation::VerifyProof => {
                // Verification is read-only - just record the request
```
Replacement:
```rust
            HealthcareOperation::VerifyProof => {
                let proof: HealthcareProofEnvelope = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;
                if !Self::v_healthcare_proof_exists(view, &proof.proof_id)? {
                    return Ok(HealthcareExecutionResult::failure("Proof not found"));
                }
```
Printed by libtest while mutated:
```
test verify_proof_succeeds_for_a_proof_that_does_not_exist ... FAILED
```

#### I7 renewal refuses a terminated membership

* occurrences checked before applying: **1** (expected 1)
* covering test: `renewing_a_terminated_membership_makes_it_active_again` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `32bc8429df0160d0` -> replacement `6591497dec21c340`
* verdict: **KILLED**

Anchor:
```rust
                if membership.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Only issuer can renew"));
                }
```
Replacement:
```rust
                if membership.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Only issuer can renew"));
                }

                if membership.status == MembershipStatus::Terminated {
                    return Ok(HealthcareExecutionResult::failure("Membership is terminated"));
                }
```
Printed by libtest while mutated:
```
test renewing_a_terminated_membership_makes_it_active_again ... FAILED
```

#### I8 controlled substances refuse every status change

* occurrences checked before applying: **1** (expected 1)
* covering test: `the_controlled_substance_guard_covers_only_the_transfer_status` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `d8d8658297936098` -> replacement `84b50d3e009d3083`
* verdict: **KILLED**

Anchor:
```rust
                if prescription.is_controlled && d.status == PrescriptionStatus::TransferRequested {
```
Replacement:
```rust
                if prescription.is_controlled {
```
Printed by libtest while mutated:
```
test the_controlled_substance_guard_covers_only_the_transfer_status ... FAILED
```

#### I9 the zero-refill fill guard drops its status escape

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_prescription_with_no_refills_but_active_status_can_be_filled_once_more` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `867c9d389b23ba2e` -> replacement `b046856b7fe66190`
* verdict: **KILLED**

Anchor:
```rust
                if prescription.refills_remaining == 0 && prescription.status != PrescriptionStatus::Active {
                    return Ok(HealthcareExecutionResult::failure("No fills remaining"));
                }
```
Replacement:
```rust
                if prescription.refills_remaining == 0 {
                    return Ok(HealthcareExecutionResult::failure("No fills remaining"));
                }
```
Printed by libtest while mutated:
```
test a_prescription_with_no_refills_but_active_status_can_be_filled_once_more ... FAILED
```

#### I10 consent revocation also admits the subject

* occurrences checked before applying: **1** (expected 1)
* covering test: `the_subject_of_a_consent_can_neither_grant_nor_revoke_it` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `578a742bd05c8ed6` -> replacement `a9fbfa01d44b855c`
* verdict: **KILLED**

Anchor:
```rust
                if consent.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Only issuer can revoke"));
                }
```
Replacement:
```rust
                if consent.issuer_address != *sender && consent.subject_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Only issuer can revoke"));
                }
```
Printed by libtest while mutated:
```
test the_subject_of_a_consent_can_neither_grant_nor_revoke_it ... FAILED
```

#### I12 partial fill stops writing the status

* occurrences checked before applying: **1** (expected 1)
* covering test: `one_partial_fill_records_exactly_one` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `d4c02ed84ed76761` -> replacement `d4db4501e99e4ecc`
* verdict: **KILLED**

Anchor:
```rust
                Self::v_update_prescription_status(
                    view,
                    &d.prescription_id,
                    PrescriptionStatus::PartiallyFilled,
                    block_timestamp,
                )?;
                debug!("Prescription partially filled: {:?}", d.prescription_id);
```
Replacement:
```rust
                debug!("Prescription partially filled: {:?}", d.prescription_id);
```
Printed by libtest while mutated:
```
test one_partial_fill_records_exactly_one ... FAILED
```

#### I13 partial fill stops recording the fill

* occurrences checked before applying: **1** (expected 1)
* covering test: `one_partial_fill_records_exactly_one` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `f910d58d473cf6b3` -> replacement `e3b0c44298fc1c14`
* verdict: **KILLED**

Anchor:
```rust
                Self::v_add_fill_history(
                    view,
                    &d.prescription_id,
                    d.fill_commitment,
                    block_timestamp,
                )?;
```
Replacement:
```rust
(deleted)
```
Printed by libtest while mutated:
```
test one_partial_fill_records_exactly_one ... FAILED
```

### `crates/storage/src/healthcare_store.rs`


#### F1 provider_key truncated to 16 bytes

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_provider_row_is_bincode_at_the_provider_id_key_and_indexes_every_plan` (`sumchain-storage --test healthcare_codec_parity`)
* anchor sha256[:16] `46c5eb64cb553976` -> replacement `7f6c908632c58cd4`
* verdict: **KILLED**

Anchor:
```rust
pub fn provider_key(provider_id: &ProviderId) -> &[u8] {
    provider_id
}
```
Replacement:
```rust
pub fn provider_key(provider_id: &ProviderId) -> &[u8] {
    &provider_id[..16]
}
```
Printed by libtest while mutated:
```
test a_provider_row_is_bincode_at_the_provider_id_key_and_indexes_every_plan ... FAILED
```

#### F2 provider_network_index_key truncated to 16 bytes

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_provider_row_is_bincode_at_the_provider_id_key_and_indexes_every_plan` (`sumchain-storage --test healthcare_codec_parity`)
* anchor sha256[:16] `226283148ff28891` -> replacement `95687631481f9f31`
* verdict: **KILLED**

Anchor:
```rust
pub fn provider_network_index_key(plan_id: &ProviderId) -> &[u8] {
    plan_id
}
```
Replacement:
```rust
pub fn provider_network_index_key(plan_id: &ProviderId) -> &[u8] {
    &plan_id[..16]
}
```
Printed by libtest while mutated:
```
test a_provider_row_is_bincode_at_the_provider_id_key_and_indexes_every_plan ... FAILED
```

#### F3 membership_key truncated to 16 bytes

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_membership_row_is_bincode_at_the_membership_id_key_and_indexes_its_member` (`sumchain-storage --test healthcare_codec_parity`)
* anchor sha256[:16] `9c185877c652e5ce` -> replacement `8da91328484e3d9b`
* verdict: **KILLED**

Anchor:
```rust
pub fn membership_key(membership_id: &MembershipId) -> &[u8] {
    membership_id
}
```
Replacement:
```rust
pub fn membership_key(membership_id: &MembershipId) -> &[u8] {
    &membership_id[..16]
}
```
Printed by libtest while mutated:
```
test a_membership_row_is_bincode_at_the_membership_id_key_and_indexes_its_member ... FAILED
```

#### F4 member_index_key truncated to 16 bytes

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_membership_row_is_bincode_at_the_membership_id_key_and_indexes_its_member` (`sumchain-storage --test healthcare_codec_parity`)
* anchor sha256[:16] `86a4093917ccc7b1` -> replacement `b7348ad67d35ea33`
* verdict: **KILLED**

Anchor:
```rust
pub fn member_index_key(member_nullifier: &[u8; 32]) -> &[u8] {
    member_nullifier
}
```
Replacement:
```rust
pub fn member_index_key(member_nullifier: &[u8; 32]) -> &[u8] {
    &member_nullifier[..16]
}
```
Printed by libtest while mutated:
```
test a_membership_row_is_bincode_at_the_membership_id_key_and_indexes_its_member ... FAILED
```

#### F5 consent_key truncated to 16 bytes

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_consent_row_is_bincode_at_the_consent_id_key_and_indexes_its_subject` (`sumchain-storage --test healthcare_codec_parity`)
* anchor sha256[:16] `2b212a8a0938d8ff` -> replacement `345b337a38ec50a2`
* verdict: **KILLED**

Anchor:
```rust
pub fn consent_key(consent_id: &ConsentId) -> &[u8] {
    consent_id
}
```
Replacement:
```rust
pub fn consent_key(consent_id: &ConsentId) -> &[u8] {
    &consent_id[..16]
}
```
Printed by libtest while mutated:
```
test a_consent_row_is_bincode_at_the_consent_id_key_and_indexes_its_subject ... FAILED
```

#### F6 subject_consent_index_key truncated to 16 bytes

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_consent_row_is_bincode_at_the_consent_id_key_and_indexes_its_subject` (`sumchain-storage --test healthcare_codec_parity`)
* anchor sha256[:16] `aa08fa5bfd5d9d35` -> replacement `e7979861b93630a2`
* verdict: **KILLED**

Anchor:
```rust
pub fn subject_consent_index_key(subject_nullifier: &[u8; 32]) -> &[u8] {
    subject_nullifier
}
```
Replacement:
```rust
pub fn subject_consent_index_key(subject_nullifier: &[u8; 32]) -> &[u8] {
    &subject_nullifier[..16]
}
```
Printed by libtest while mutated:
```
test a_consent_row_is_bincode_at_the_consent_id_key_and_indexes_its_subject ... FAILED
```

#### F7 prescription_key truncated to 16 bytes

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_prescription_row_is_bincode_and_indexes_both_its_patient_and_its_prescriber` (`sumchain-storage --test healthcare_codec_parity`)
* anchor sha256[:16] `183c0ec25e5bc80d` -> replacement `2a78861699234150`
* verdict: **KILLED**

Anchor:
```rust
pub fn prescription_key(prescription_id: &PrescriptionId) -> &[u8] {
    prescription_id
}
```
Replacement:
```rust
pub fn prescription_key(prescription_id: &PrescriptionId) -> &[u8] {
    &prescription_id[..16]
}
```
Printed by libtest while mutated:
```
test a_prescription_row_is_bincode_and_indexes_both_its_patient_and_its_prescriber ... FAILED
```

#### F8 patient_rx_index_key truncated to 16 bytes

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_prescription_row_is_bincode_and_indexes_both_its_patient_and_its_prescriber` (`sumchain-storage --test healthcare_codec_parity`)
* anchor sha256[:16] `3e54ea5ee3f5dd11` -> replacement `dfea8740fa58b80c`
* verdict: **KILLED**

Anchor:
```rust
pub fn patient_rx_index_key(patient_nullifier: &[u8; 32]) -> &[u8] {
    patient_nullifier
}
```
Replacement:
```rust
pub fn patient_rx_index_key(patient_nullifier: &[u8; 32]) -> &[u8] {
    &patient_nullifier[..16]
}
```
Printed by libtest while mutated:
```
test a_prescription_row_is_bincode_and_indexes_both_its_patient_and_its_prescriber ... FAILED
```

#### F9 prescriber_rx_index_key truncated to 16 bytes

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_prescription_row_is_bincode_and_indexes_both_its_patient_and_its_prescriber` (`sumchain-storage --test healthcare_codec_parity`)
* anchor sha256[:16] `93c9a403a2cc0ee7` -> replacement `8a361a7803406085`
* verdict: **KILLED**

Anchor:
```rust
pub fn prescriber_rx_index_key(prescriber_id: &ProviderId) -> &[u8] {
    prescriber_id
}
```
Replacement:
```rust
pub fn prescriber_rx_index_key(prescriber_id: &ProviderId) -> &[u8] {
    &prescriber_id[..16]
}
```
Printed by libtest while mutated:
```
test a_prescription_row_is_bincode_and_indexes_both_its_patient_and_its_prescriber ... FAILED
```

#### F10 healthcare_proof_key truncated to 16 bytes

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_proof_row_is_bincode_at_the_proof_id_key_and_writes_no_index` (`sumchain-storage --test healthcare_codec_parity`)
* anchor sha256[:16] `d252f91017a4033e` -> replacement `1b0452ef94b44938`
* verdict: **KILLED**

Anchor:
```rust
pub fn healthcare_proof_key(proof_id: &ProofId) -> &[u8] {
    proof_id
}
```
Replacement:
```rust
pub fn healthcare_proof_key(proof_id: &ProofId) -> &[u8] {
    &proof_id[..16]
}
```
Printed by libtest while mutated:
```
test a_proof_row_is_bincode_at_the_proof_id_key_and_writes_no_index ... FAILED
```

#### G1 encode_provider writes only the id

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_provider_row_is_bincode_at_the_provider_id_key_and_indexes_every_plan` (`sumchain-storage --test healthcare_codec_parity`)
* anchor sha256[:16] `17c3d8225ba4a49b` -> replacement `debbe86d9faa8d5c`
* verdict: **KILLED**

Anchor:
```rust
pub fn encode_provider(p: &ProviderProfile) -> Result<Vec<u8>> {
    bincode::serialize(p).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Replacement:
```rust
pub fn encode_provider(p: &ProviderProfile) -> Result<Vec<u8>> {
    bincode::serialize(&p.provider_id).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Printed by libtest while mutated:
```
test a_provider_row_is_bincode_at_the_provider_id_key_and_indexes_every_plan ... FAILED
```

#### G2 encode_membership writes only the id

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_membership_row_is_bincode_at_the_membership_id_key_and_indexes_its_member` (`sumchain-storage --test healthcare_codec_parity`)
* anchor sha256[:16] `f22d1271e8df8a34` -> replacement `3bf57c17ef345833`
* verdict: **KILLED**

Anchor:
```rust
pub fn encode_membership(m: &MembershipRecord) -> Result<Vec<u8>> {
    bincode::serialize(m).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Replacement:
```rust
pub fn encode_membership(m: &MembershipRecord) -> Result<Vec<u8>> {
    bincode::serialize(&m.membership_id).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Printed by libtest while mutated:
```
test a_membership_row_is_bincode_at_the_membership_id_key_and_indexes_its_member ... FAILED
```

#### G3 encode_consent writes only the id

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_consent_row_is_bincode_at_the_consent_id_key_and_indexes_its_subject` (`sumchain-storage --test healthcare_codec_parity`)
* anchor sha256[:16] `1e8fddb2956893b7` -> replacement `3d1952a7421ee14c`
* verdict: **KILLED**

Anchor:
```rust
pub fn encode_consent(c: &ConsentEnvelope) -> Result<Vec<u8>> {
    bincode::serialize(c).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Replacement:
```rust
pub fn encode_consent(c: &ConsentEnvelope) -> Result<Vec<u8>> {
    bincode::serialize(&c.consent_id).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Printed by libtest while mutated:
```
test a_consent_row_is_bincode_at_the_consent_id_key_and_indexes_its_subject ... FAILED
```

#### G4 encode_prescription writes only the id

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_prescription_row_is_bincode_and_indexes_both_its_patient_and_its_prescriber` (`sumchain-storage --test healthcare_codec_parity`)
* anchor sha256[:16] `76003765d558bf4e` -> replacement `b1991179fc339093`
* verdict: **KILLED**

Anchor:
```rust
pub fn encode_prescription(p: &Prescription) -> Result<Vec<u8>> {
    bincode::serialize(p).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Replacement:
```rust
pub fn encode_prescription(p: &Prescription) -> Result<Vec<u8>> {
    bincode::serialize(&p.prescription_id).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Printed by libtest while mutated:
```
test a_prescription_row_is_bincode_and_indexes_both_its_patient_and_its_prescriber ... FAILED
```

#### G5 encode_healthcare_proof writes only the id

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_proof_row_is_bincode_at_the_proof_id_key_and_writes_no_index` (`sumchain-storage --test healthcare_codec_parity`)
* anchor sha256[:16] `185428e7d3107370` -> replacement `194ff85e9534c475`
* verdict: **KILLED**

Anchor:
```rust
pub fn encode_healthcare_proof(p: &HealthcareProofEnvelope) -> Result<Vec<u8>> {
    bincode::serialize(p).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Replacement:
```rust
pub fn encode_healthcare_proof(p: &HealthcareProofEnvelope) -> Result<Vec<u8>> {
    bincode::serialize(&p.proof_id).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Printed by libtest while mutated:
```
test a_proof_row_is_bincode_at_the_proof_id_key_and_writes_no_index ... FAILED
```

#### G6 encode_provider_ids keeps only the first entry

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_second_provider_in_one_plan_appends_to_the_same_list` (`sumchain-storage --test healthcare_codec_parity`)
* anchor sha256[:16] `34add7d180158864` -> replacement `251c5b0c3669951f`
* verdict: **KILLED**

Anchor:
```rust
pub fn encode_provider_ids(ids: &[ProviderId]) -> Result<Vec<u8>> {
    bincode::serialize(ids).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Replacement:
```rust
pub fn encode_provider_ids(ids: &[ProviderId]) -> Result<Vec<u8>> {
    bincode::serialize(&ids[..ids.len().min(1)]).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Printed by libtest while mutated:
```
test a_second_provider_in_one_plan_appends_to_the_same_list ... FAILED
```

#### G7 encode_membership_ids keeps only the first entry

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_second_membership_for_one_member_appends_to_the_same_list` (`sumchain-storage --test healthcare_codec_parity`)
* anchor sha256[:16] `7adb89d2468200b0` -> replacement `2e9573dc69b427c9`
* verdict: **KILLED**

Anchor:
```rust
pub fn encode_membership_ids(ids: &[MembershipId]) -> Result<Vec<u8>> {
    bincode::serialize(ids).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Replacement:
```rust
pub fn encode_membership_ids(ids: &[MembershipId]) -> Result<Vec<u8>> {
    bincode::serialize(&ids[..ids.len().min(1)]).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Printed by libtest while mutated:
```
test a_second_membership_for_one_member_appends_to_the_same_list ... FAILED
```

#### G8 encode_consent_ids keeps only the first entry

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_second_consent_for_one_subject_appends_to_the_same_list` (`sumchain-storage --test healthcare_codec_parity`)
* anchor sha256[:16] `834d70ddbd77ec69` -> replacement `321e49d22d8a40b5`
* verdict: **KILLED**

Anchor:
```rust
pub fn encode_consent_ids(ids: &[ConsentId]) -> Result<Vec<u8>> {
    bincode::serialize(ids).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Replacement:
```rust
pub fn encode_consent_ids(ids: &[ConsentId]) -> Result<Vec<u8>> {
    bincode::serialize(&ids[..ids.len().min(1)]).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Printed by libtest while mutated:
```
test a_second_consent_for_one_subject_appends_to_the_same_list ... FAILED
```

#### G9 encode_prescription_ids keeps only the first entry

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_second_prescription_appends_to_both_of_its_lists` (`sumchain-storage --test healthcare_codec_parity`)
* anchor sha256[:16] `1e5b3d1072ccc0dc` -> replacement `0a133b2da14fc45f`
* verdict: **KILLED**

Anchor:
```rust
pub fn encode_prescription_ids(ids: &[PrescriptionId]) -> Result<Vec<u8>> {
    bincode::serialize(ids).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Replacement:
```rust
pub fn encode_prescription_ids(ids: &[PrescriptionId]) -> Result<Vec<u8>> {
    bincode::serialize(&ids[..ids.len().min(1)]).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Printed by libtest while mutated:
```
test a_second_prescription_appends_to_both_of_its_lists ... FAILED
```

#### G10 decode_provider reads one byte short

* occurrences checked before applying: **1** (expected 1)
* covering test: `every_round_trip_returns_the_value_that_was_written` (`sumchain-storage --test healthcare_codec_parity`)
* anchor sha256[:16] `30d815433515fdf5` -> replacement `ef7ef472311e7eea`
* verdict: **KILLED**

Anchor:
```rust
pub fn decode_provider(bytes: &[u8]) -> Result<ProviderProfile> {
    bincode::deserialize(bytes).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Replacement:
```rust
pub fn decode_provider(bytes: &[u8]) -> Result<ProviderProfile> {
    bincode::deserialize(&bytes[..bytes.len().saturating_sub(1)]).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Printed by libtest while mutated:
```
test every_round_trip_returns_the_value_that_was_written ... FAILED
```

#### G11 decode_membership reads one byte short

* occurrences checked before applying: **1** (expected 1)
* covering test: `every_round_trip_returns_the_value_that_was_written` (`sumchain-storage --test healthcare_codec_parity`)
* anchor sha256[:16] `aed0402084196b8d` -> replacement `e524509998eb3de3`
* verdict: **KILLED**

Anchor:
```rust
pub fn decode_membership(bytes: &[u8]) -> Result<MembershipRecord> {
    bincode::deserialize(bytes).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Replacement:
```rust
pub fn decode_membership(bytes: &[u8]) -> Result<MembershipRecord> {
    bincode::deserialize(&bytes[..bytes.len().saturating_sub(1)]).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Printed by libtest while mutated:
```
test every_round_trip_returns_the_value_that_was_written ... FAILED
```

#### G12 decode_consent reads one byte short

* occurrences checked before applying: **1** (expected 1)
* covering test: `every_round_trip_returns_the_value_that_was_written` (`sumchain-storage --test healthcare_codec_parity`)
* anchor sha256[:16] `189e13d8ebf41c09` -> replacement `0f99e7d2cf331a11`
* verdict: **KILLED**

Anchor:
```rust
pub fn decode_consent(bytes: &[u8]) -> Result<ConsentEnvelope> {
    bincode::deserialize(bytes).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Replacement:
```rust
pub fn decode_consent(bytes: &[u8]) -> Result<ConsentEnvelope> {
    bincode::deserialize(&bytes[..bytes.len().saturating_sub(1)]).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Printed by libtest while mutated:
```
test every_round_trip_returns_the_value_that_was_written ... FAILED
```

#### G13 decode_prescription reads one byte short

* occurrences checked before applying: **1** (expected 1)
* covering test: `every_round_trip_returns_the_value_that_was_written` (`sumchain-storage --test healthcare_codec_parity`)
* anchor sha256[:16] `9027c49498d98399` -> replacement `4c3919edb2bbcd1c`
* verdict: **KILLED**

Anchor:
```rust
pub fn decode_prescription(bytes: &[u8]) -> Result<Prescription> {
    bincode::deserialize(bytes).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Replacement:
```rust
pub fn decode_prescription(bytes: &[u8]) -> Result<Prescription> {
    bincode::deserialize(&bytes[..bytes.len().saturating_sub(1)]).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Printed by libtest while mutated:
```
test every_round_trip_returns_the_value_that_was_written ... FAILED
```

#### G14 decode_healthcare_proof reads one byte short

* occurrences checked before applying: **1** (expected 1)
* covering test: `every_round_trip_returns_the_value_that_was_written` (`sumchain-storage --test healthcare_codec_parity`)
* anchor sha256[:16] `400b7d245783cdf7` -> replacement `9e811c408cc4119b`
* verdict: **KILLED**

Anchor:
```rust
pub fn decode_healthcare_proof(bytes: &[u8]) -> Result<HealthcareProofEnvelope> {
    bincode::deserialize(bytes).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Replacement:
```rust
pub fn decode_healthcare_proof(bytes: &[u8]) -> Result<HealthcareProofEnvelope> {
    bincode::deserialize(&bytes[..bytes.len().saturating_sub(1)]).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Printed by libtest while mutated:
```
test every_round_trip_returns_the_value_that_was_written ... FAILED
```

#### G15 decode_provider_ids reads corruption as an empty list

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_malformed_row_is_an_error_from_every_decoding_reader` (`sumchain-storage --test healthcare_codec_parity`)
* anchor sha256[:16] `b4533579768220b3` -> replacement `affcb503468a15f8`
* verdict: **KILLED**

Anchor:
```rust
pub fn decode_provider_ids(bytes: &[u8]) -> Result<Vec<ProviderId>> {
    bincode::deserialize(bytes).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Replacement:
```rust
pub fn decode_provider_ids(bytes: &[u8]) -> Result<Vec<ProviderId>> {
    Ok(bincode::deserialize(bytes).unwrap_or_default())
}
```
Printed by libtest while mutated:
```
test a_malformed_row_is_an_error_from_every_decoding_reader ... FAILED
```

#### G16 decode_membership_ids reads corruption as an empty list

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_malformed_row_is_an_error_from_every_decoding_reader` (`sumchain-storage --test healthcare_codec_parity`)
* anchor sha256[:16] `9d58d288b18c0ae5` -> replacement `e39c6e446e977470`
* verdict: **KILLED**

Anchor:
```rust
pub fn decode_membership_ids(bytes: &[u8]) -> Result<Vec<MembershipId>> {
    bincode::deserialize(bytes).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Replacement:
```rust
pub fn decode_membership_ids(bytes: &[u8]) -> Result<Vec<MembershipId>> {
    Ok(bincode::deserialize(bytes).unwrap_or_default())
}
```
Printed by libtest while mutated:
```
test a_malformed_row_is_an_error_from_every_decoding_reader ... FAILED
```

#### G17 decode_consent_ids reads corruption as an empty list

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_malformed_row_is_an_error_from_every_decoding_reader` (`sumchain-storage --test healthcare_codec_parity`)
* anchor sha256[:16] `5ed6664597109d4b` -> replacement `05d5e1fbf77fce26`
* verdict: **KILLED**

Anchor:
```rust
pub fn decode_consent_ids(bytes: &[u8]) -> Result<Vec<ConsentId>> {
    bincode::deserialize(bytes).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Replacement:
```rust
pub fn decode_consent_ids(bytes: &[u8]) -> Result<Vec<ConsentId>> {
    Ok(bincode::deserialize(bytes).unwrap_or_default())
}
```
Printed by libtest while mutated:
```
test a_malformed_row_is_an_error_from_every_decoding_reader ... FAILED
```

#### G18 decode_prescription_ids reads corruption as an empty list

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_malformed_row_is_an_error_from_every_decoding_reader` (`sumchain-storage --test healthcare_codec_parity`)
* anchor sha256[:16] `0ba3f1c6ada3bb37` -> replacement `c5369333507ca515`
* verdict: **KILLED**

Anchor:
```rust
pub fn decode_prescription_ids(bytes: &[u8]) -> Result<Vec<PrescriptionId>> {
    bincode::deserialize(bytes).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Replacement:
```rust
pub fn decode_prescription_ids(bytes: &[u8]) -> Result<Vec<PrescriptionId>> {
    Ok(bincode::deserialize(bytes).unwrap_or_default())
}
```
Printed by libtest while mutated:
```
test a_malformed_row_is_an_error_from_every_decoding_reader ... FAILED
```

#### G19 committed network-index remove becomes conditional

* occurrences checked before applying: **1** (expected 1)
* covering test: `removing_an_affiliation_that_was_never_there_still_writes_an_empty_index` (`sumchain-storage --test healthcare_codec_parity`)
* anchor sha256[:16] `3cc415c52caa4e8e` -> replacement `fd1b371c6f5e0b73`
* verdict: **KILLED**

Anchor:
```rust
        ids.retain(|id| id != provider_id);
        let bytes = encode_provider_ids(&ids)?;
```
Replacement:
```rust
        let before = ids.len();
        ids.retain(|id| id != provider_id);
        if ids.len() == before {
            return Ok(());
        }
        let bytes = encode_provider_ids(&ids)?;
```
Printed by libtest while mutated:
```
test removing_an_affiliation_that_was_never_there_still_writes_an_empty_index ... FAILED
```

### `crates/state/src/executor.rs`


#### J1 live arm sends the proposer as the sender

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_membership_finds_a_provider_registered_earlier_in_the_same_block` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `7003f8daf0f294c1` -> replacement `ea336892cdc09136`
* verdict: **KILLED**

Anchor:
```rust
                        let result = HealthcareExecutor::execute(
                            view,
                            &v2_tx.from,
                            &healthcare_data,
                            proposer,
                            v2_tx.fee,
                            block_height,
                            0, // block_timestamp placeholder
```
Replacement:
```rust
                        let result = HealthcareExecutor::execute(
                            view,
                            proposer,
                            &healthcare_data,
                            proposer,
                            v2_tx.fee,
                            block_height,
                            0, // block_timestamp placeholder
```
Printed by libtest while mutated:
```
test a_membership_finds_a_provider_registered_earlier_in_the_same_block ... FAILED
```

#### J2 v2 arm sends the proposer as the sender

* occurrences checked before applying: **1** (expected 1)
* covering test: `the_v2_dispatch_surface_also_stages_healthcare` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `91bbdc4ea395bc5b` -> replacement `a823ca75bd483453`
* verdict: **KILLED**

Anchor:
```rust
                let result = HealthcareExecutor::execute(
                    view,
                    &tx.from,
                    healthcare_data,
                    proposer,
                    tx.fee,
                    block_height,
                    0, // block_timestamp placeholder
```
Replacement:
```rust
                let result = HealthcareExecutor::execute(
                    view,
                    proposer,
                    healthcare_data,
                    proposer,
                    tx.fee,
                    block_height,
                    0, // block_timestamp placeholder
```
Printed by libtest while mutated:
```
test the_v2_dispatch_surface_also_stages_healthcare ... FAILED
```

#### J3 live arm passes the real block timestamp

* occurrences checked before applying: **1** (expected 1)
* covering test: `the_block_timestamp_reaching_healthcare_operations_is_always_zero` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `7003f8daf0f294c1` -> replacement `2c38851aed8ec04d`
* verdict: **KILLED**

Anchor:
```rust
                        let result = HealthcareExecutor::execute(
                            view,
                            &v2_tx.from,
                            &healthcare_data,
                            proposer,
                            v2_tx.fee,
                            block_height,
                            0, // block_timestamp placeholder
```
Replacement:
```rust
                        let result = HealthcareExecutor::execute(
                            view,
                            &v2_tx.from,
                            &healthcare_data,
                            proposer,
                            v2_tx.fee,
                            block_height,
                            block_timestamp,
```
Printed by libtest while mutated:
```
test the_block_timestamp_reaching_healthcare_operations_is_always_zero ... FAILED
```

#### J4 v2 arm passes the real block timestamp

* occurrences checked before applying: **1** (expected 1)
* covering test: `the_v2_dispatch_surface_also_stages_healthcare` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `91bbdc4ea395bc5b` -> replacement `6afb7015f4266f29`
* verdict: **KILLED**

Anchor:
```rust
                let result = HealthcareExecutor::execute(
                    view,
                    &tx.from,
                    healthcare_data,
                    proposer,
                    tx.fee,
                    block_height,
                    0, // block_timestamp placeholder
```
Replacement:
```rust
                let result = HealthcareExecutor::execute(
                    view,
                    &tx.from,
                    healthcare_data,
                    proposer,
                    tx.fee,
                    block_height,
                    block_timestamp,
```
Printed by libtest while mutated:
```
test the_v2_dispatch_surface_also_stages_healthcare ... FAILED
```

#### J5 live arm reports a neighbouring subsystem's failure code

* occurrences checked before applying: **1** (expected 1)
* covering test: `without_the_provider_the_same_membership_is_refused` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `c1403d253c7d52fb` -> replacement `7be0e3438f515619`
* verdict: **KILLED**

Anchor:
```rust
                            Ok(TxExecutionResult {
                                tx_hash,
                                status: TxStatus::Failed(14), // Healthcare operation failed
                                fee_paid: 0,
                            })
```
Replacement:
```rust
                            Ok(TxExecutionResult {
                                tx_hash,
                                status: TxStatus::Failed(11), // Healthcare operation failed
                                fee_paid: 0,
                            })
```
Printed by libtest while mutated:
```
test without_the_provider_the_same_membership_is_refused ... FAILED
```

#### J6 v2 arm reports a neighbouring subsystem's failure code

* occurrences checked before applying: **1** (expected 1)
* covering test: `the_v2_dispatch_surface_also_stages_healthcare` (`sumchain-state --test healthcare_routing`)
* anchor sha256[:16] `c1b0f770a6f40f89` -> replacement `d72cd00eef973dff`
* verdict: **KILLED**

Anchor:
```rust
                    Ok(TxExecutionResult {
                        tx_hash,
                        status: TxStatus::Failed(14), // Healthcare operation failed
                        fee_paid: 0,
                    })
```
Replacement:
```rust
                    Ok(TxExecutionResult {
                        tx_hash,
                        status: TxStatus::Failed(11), // Healthcare operation failed
                        fee_paid: 0,
                    })
```
Printed by libtest while mutated:
```
test the_v2_dispatch_surface_also_stages_healthcare ... FAILED
```

## Totals and post-run hashes

```
=== totals ===
  killed: 116
  declared: 116   scored: 116

=== post-run hashes (authoritative) ===
  MATCH   456c553ccbc6e739c3a23135e05950af02dd462c6e2cf5c4546f212e4138af0f  crates/state/src/healthcare_view.rs
  MATCH   4cfefc3b35701dcba65015f1e76aa1bbb328ff143052e87d94eee7d2063f211c  crates/state/src/healthcare_executor.rs
  MATCH   be244b8dd8e3bac70570cd6f3f2bafb93211eace6842816f838e204cd608bb3d  crates/state/src/executor.rs
  MATCH   86fa1c1e2e852d1a805d74e9246371971f3f9fac35e2cd478b9f2c6d7a1db928  crates/storage/src/healthcare_store.rs
  all four byte-identical to pre-run: True

=== anchors resolve exactly once again ===
  116/116
```
