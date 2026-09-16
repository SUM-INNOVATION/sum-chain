# Agreement routing: mutation battery

NOT DEPLOYABLE ON ITS OWN, like the rest of this lane.


Each mutation is applied to the tree that this commit contains, one at a time,
and the NAMED covering test is run. A kill requires that test to appear in
libtest's output AND to have failed. A mutation whose anchor does not resolve
exactly once aborts the whole run before anything is applied; one that does not
compile, and one whose covering test does not appear, are separate categories
that never count as kills. Restoration happens in a `finally` and on
SIGINT/SIGTERM, and every restore is checked against the pre-run hash.

Whole-tree text scanning for leftover replacements is diagnostic only. A
replacement is usable as a residue marker only if it does not already occur in
the pristine tree; ten of these do occur there -- strings such as `Ok(false)`,
`Ok(())`, `.map_err(StateError::Storage)` and outright deletions -- so finding
them proves nothing. The final evidence is 62 mutations total, 52 scanned
specifically by text, and 10 covered by exact file hashes alone. The
authoritative residue check for all 62 is the pre/post hash of every mutated
file, printed at the end of this document.


## Pre-run file hashes

```
  ea1a65df4b5ed9ff3882102a192fce5b9be7ce2e02116897028ca1d2453447ce  crates/state/src/agreement_view.rs
  b010e0a47c287144a3dba2b1210df11a935a40bdbe561ce901e9a376e90441f9  crates/state/src/agreement_executor.rs
  de8f6a5bbfe648612744b1e71bfdc5db159ed8bb9d88dc4ee4236f2926a97854  crates/state/src/executor.rs
  2443cc962f2e6337c3dc996a1888a11b6931305a1e69d74806ca2c0d53d58e21  crates/storage/src/agreement_store.rs
```


## The 62 mutations


### `crates/state/src/agreement_view.rs`


#### A1 agreement read sees nothing

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_signature_finds_an_agreement_committed_earlier_in_the_same_block` (`sumchain-state --test agreement_routing`)
* anchor sha256[:16] `1029fda3206357be` -> replacement `c832b86ec08ac5f2`
* verdict: **KILLED**

Anchor:
```rust
        match view
            .get(cf::AGREEMENT_COMMITMENTS, commitment_key(agreement_id))
            .map_err(StateError::Storage)?
        {
```
Replacement:
```rust
        match None::<Vec<u8>> {
```
Printed by libtest while mutated:
```
test a_signature_finds_an_agreement_committed_earlier_in_the_same_block ... FAILED
```

#### A2 signature read sees nothing

* occurrences checked before applying: **1** (expected 1)
* covering test: `revoking_a_signature_leaves_the_party_marked_signed` (`sumchain-state --test agreement_routing`)
* anchor sha256[:16] `933f4b3405ee1346` -> replacement `c832b86ec08ac5f2`
* verdict: **KILLED**

Anchor:
```rust
        match view
            .get(cf::AGREEMENT_SIGNATURES, signature_key(signature_id))
            .map_err(StateError::Storage)?
        {
```
Replacement:
```rust
        match None::<Vec<u8>> {
```
Printed by libtest while mutated:
```
test revoking_a_signature_leaves_the_party_marked_signed ... FAILED
```

#### A3 attestation read sees nothing

* occurrences checked before applying: **1** (expected 1)
* covering test: `corrupt_rows_error_through_dispatch_with_exactly_this_staged` (`sumchain-state --test agreement_routing`)
* anchor sha256[:16] `db03e04ac0723b78` -> replacement `c832b86ec08ac5f2`
* verdict: **KILLED**

Anchor:
```rust
        match view
            .get(cf::AGREEMENT_ATTESTATIONS, attestation_key(attestation_id))
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

#### A4 ip-action read sees nothing

* occurrences checked before applying: **1** (expected 1)
* covering test: `corrupt_rows_error_through_dispatch_with_exactly_this_staged` (`sumchain-state --test agreement_routing`)
* anchor sha256[:16] `334090f296797389` -> replacement `c832b86ec08ac5f2`
* verdict: **KILLED**

Anchor:
```rust
        match view
            .get(cf::AGREEMENT_IP_ACTIONS, ip_action_key(action_id))
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

#### A5 executor-link read sees nothing

* occurrences checked before applying: **1** (expected 1)
* covering test: `an_executor_link_is_created_and_activated_within_one_block` (`sumchain-state --test agreement_routing`)
* anchor sha256[:16] `c3b6de167b543181` -> replacement `c832b86ec08ac5f2`
* verdict: **KILLED**

Anchor:
```rust
        match view
            .get(cf::AGREEMENT_EXECUTOR_LINKS, executor_link_key(link_id))
            .map_err(StateError::Storage)?
        {
```
Replacement:
```rust
        match None::<Vec<u8>> {
```
Printed by libtest while mutated:
```
test an_executor_link_is_created_and_activated_within_one_block ... FAILED
```

#### A6 party index read sees nothing

* occurrences checked before applying: **1** (expected 1)
* covering test: `two_agreements_for_one_party_accumulate_in_the_index` (`sumchain-state --test agreement_routing`)
* anchor sha256[:16] `02b5c5bcc7533241` -> replacement `c832b86ec08ac5f2`
* verdict: **KILLED**

Anchor:
```rust
        match view
            .get(cf::AGREEMENT_PARTY_INDEX, party_index_key(party_ref_hash))
            .map_err(StateError::Storage)?
        {
```
Replacement:
```rust
        match None::<Vec<u8>> {
```
Printed by libtest while mutated:
```
test two_agreements_for_one_party_accumulate_in_the_index ... FAILED
```

#### A7 executor index read sees nothing

* occurrences checked before applying: **1** (expected 1)
* covering test: `two_links_for_one_executor_accumulate_in_the_index` (`sumchain-state --test agreement_routing`)
* anchor sha256[:16] `950ba9baca81fc97` -> replacement `c832b86ec08ac5f2`
* verdict: **KILLED**

Anchor:
```rust
        match view
            .get(cf::AGREEMENT_EXECUTOR_INDEX, executor_index_key(executor))
            .map_err(StateError::Storage)?
        {
```
Replacement:
```rust
        match None::<Vec<u8>> {
```
Printed by libtest while mutated:
```
test two_links_for_one_executor_accumulate_in_the_index ... FAILED
```

#### B1 agreement exists always false

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_duplicate_agreement_id_in_the_same_block_is_refused` (`sumchain-state --test agreement_routing`)
* anchor sha256[:16] `b9c4edec72f0c127` -> replacement `e3b3651260f4ca5a`
* verdict: **KILLED**

Anchor:
```rust
        view.contains(cf::AGREEMENT_COMMITMENTS, commitment_key(agreement_id))
            .map_err(StateError::Storage)
```
Replacement:
```rust
        Ok(false)
```
Printed by libtest while mutated:
```
test a_duplicate_agreement_id_in_the_same_block_is_refused ... FAILED
```

#### B2 signature exists always false

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_duplicate_signature_id_in_the_same_block_is_refused` (`sumchain-state --test agreement_routing`)
* anchor sha256[:16] `f387d47df6da455a` -> replacement `e3b3651260f4ca5a`
* verdict: **KILLED**

Anchor:
```rust
        view.contains(cf::AGREEMENT_SIGNATURES, signature_key(signature_id))
            .map_err(StateError::Storage)
```
Replacement:
```rust
        Ok(false)
```
Printed by libtest while mutated:
```
test a_duplicate_signature_id_in_the_same_block_is_refused ... FAILED
```

#### B3 attestation exists always false

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_duplicate_attestation_in_the_same_block_is_refused` (`sumchain-state --test agreement_routing`)
* anchor sha256[:16] `cb597ee9bac68743` -> replacement `e3b3651260f4ca5a`
* verdict: **KILLED**

Anchor:
```rust
        view.contains(cf::AGREEMENT_ATTESTATIONS, attestation_key(attestation_id))
            .map_err(StateError::Storage)
```
Replacement:
```rust
        Ok(false)
```
Printed by libtest while mutated:
```
test a_duplicate_attestation_in_the_same_block_is_refused ... FAILED
```

#### B4 ip-action exists always false

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_duplicate_ip_action_in_the_same_block_is_refused` (`sumchain-state --test agreement_routing`)
* anchor sha256[:16] `097116b94e38c038` -> replacement `e3b3651260f4ca5a`
* verdict: **KILLED**

Anchor:
```rust
        view.contains(cf::AGREEMENT_IP_ACTIONS, ip_action_key(action_id))
            .map_err(StateError::Storage)
```
Replacement:
```rust
        Ok(false)
```
Printed by libtest while mutated:
```
test a_duplicate_ip_action_in_the_same_block_is_refused ... FAILED
```

#### B5 executor-link exists always false

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_duplicate_executor_link_id_in_the_same_block_is_refused` (`sumchain-state --test agreement_routing`)
* anchor sha256[:16] `49303a61abe55c22` -> replacement `e3b3651260f4ca5a`
* verdict: **KILLED**

Anchor:
```rust
        view.contains(cf::AGREEMENT_EXECUTOR_LINKS, executor_link_key(link_id))
            .map_err(StateError::Storage)
```
Replacement:
```rust
        Ok(false)
```
Printed by libtest while mutated:
```
test a_duplicate_executor_link_id_in_the_same_block_is_refused ... FAILED
```

#### B6 proof exists always false

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_duplicate_proof_in_the_same_block_is_refused` (`sumchain-state --test agreement_routing`)
* anchor sha256[:16] `fd3e5b732a26416b` -> replacement `e3b3651260f4ca5a`
* verdict: **KILLED**

Anchor:
```rust
        view.contains(cf::AGREEMENT_PROOFS, proof_key(proof_id))
            .map_err(StateError::Storage)
```
Replacement:
```rust
        Ok(false)
```
Printed by libtest while mutated:
```
test a_duplicate_proof_in_the_same_block_is_refused ... FAILED
```

#### C1 party index never written

* occurrences checked before applying: **1** (expected 1)
* covering test: `two_agreements_for_one_party_accumulate_in_the_index` (`sumchain-state --test agreement_routing`)
* anchor sha256[:16] `2925cb859e349b65` -> replacement `e3b0c44298fc1c14`
* verdict: **KILLED**

Anchor:
```rust
        for party in &agreement.parties {
            Self::v_add_to_party_index(view, &party.party_ref.as_hash(), &agreement.agreement_id)?;
        }
```
Replacement:
```rust
(deleted)
```
Printed by libtest while mutated:
```
test two_agreements_for_one_party_accumulate_in_the_index ... FAILED
```

#### C2 signature never written

* occurrences checked before applying: **1** (expected 1)
* covering test: `published_agreement_rows_survive_a_database_restart` (`sumchain-state --test agreement_routing`)
* anchor sha256[:16] `ae6751beecd3cea0` -> replacement `8573d6b029c2abf7`
* verdict: **KILLED**

Anchor:
```rust
        let bytes = encode_signature(signature).map_err(StateError::Storage)?;
        view.put(
            cf::AGREEMENT_SIGNATURES,
            signature_key(&signature.signature_id),
            &bytes,
        )
        .map_err(StateError::Storage)
```
Replacement:
```rust
        let _ = signature;
        Ok(())
```
Printed by libtest while mutated:
```
test published_agreement_rows_survive_a_database_restart ... FAILED
```

#### C3 attestation never written

* occurrences checked before applying: **1** (expected 1)
* covering test: `an_abandoned_block_leaves_all_eight_families_untouched` (`sumchain-state --test agreement_routing`)
* anchor sha256[:16] `126edde1b2bbac8f` -> replacement `f1c794c7ca8fc8d8`
* verdict: **KILLED**

Anchor:
```rust
        let bytes = encode_attestation(attestation).map_err(StateError::Storage)?;
        view.put(
            cf::AGREEMENT_ATTESTATIONS,
            attestation_key(&attestation.attestation_id),
            &bytes,
        )
        .map_err(StateError::Storage)
```
Replacement:
```rust
        let _ = attestation;
        Ok(())
```
Printed by libtest while mutated:
```
test an_abandoned_block_leaves_all_eight_families_untouched ... FAILED
```

#### C4 ip action never written

* occurrences checked before applying: **1** (expected 1)
* covering test: `an_abandoned_block_leaves_all_eight_families_untouched` (`sumchain-state --test agreement_routing`)
* anchor sha256[:16] `7a47fc87529a5d8b` -> replacement `15dcd36885ea9e1f`
* verdict: **KILLED**

Anchor:
```rust
        let bytes = encode_ip_action(action).map_err(StateError::Storage)?;
        view.put(
            cf::AGREEMENT_IP_ACTIONS,
            ip_action_key(&action.action_id),
            &bytes,
        )
        .map_err(StateError::Storage)
```
Replacement:
```rust
        let _ = action;
        Ok(())
```
Printed by libtest while mutated:
```
test an_abandoned_block_leaves_all_eight_families_untouched ... FAILED
```

#### C5 executor index never written

* occurrences checked before applying: **1** (expected 1)
* covering test: `two_links_for_one_executor_accumulate_in_the_index` (`sumchain-state --test agreement_routing`)
* anchor sha256[:16] `8c63e311cbd7a483` -> replacement `1aa44e673c6f6618`
* verdict: **KILLED**

Anchor:
```rust
        .map_err(StateError::Storage)?;
        Self::v_add_to_executor_index(view, &link.executor_contract, &link.link_id)
```
Replacement:
```rust
        .map_err(StateError::Storage)
```
Printed by libtest while mutated:
```
test two_links_for_one_executor_accumulate_in_the_index ... FAILED
```

#### C6 proof never written

* occurrences checked before applying: **1** (expected 1)
* covering test: `an_abandoned_block_leaves_all_eight_families_untouched` (`sumchain-state --test agreement_routing`)
* anchor sha256[:16] `fe59c2e57cd14772` -> replacement `4baadf37be189fb9`
* verdict: **KILLED**

Anchor:
```rust
        let bytes = encode_proof(proof).map_err(StateError::Storage)?;
        view.put(cf::AGREEMENT_PROOFS, proof_key(&proof.proof_id), &bytes)
            .map_err(StateError::Storage)
```
Replacement:
```rust
        let _ = proof;
        Ok(())
```
Printed by libtest while mutated:
```
test an_abandoned_block_leaves_all_eight_families_untouched ... FAILED
```

#### C7 signature delete is a no-op

* occurrences checked before applying: **1** (expected 1)
* covering test: `revoking_a_signature_leaves_the_party_marked_signed` (`sumchain-state --test agreement_routing`)
* anchor sha256[:16] `1dd9139a138929e5` -> replacement `0c6f8c0a301dbf42`
* verdict: **KILLED**

Anchor:
```rust
        view.delete(cf::AGREEMENT_SIGNATURES, signature_key(signature_id))
            .map_err(StateError::Storage)
```
Replacement:
```rust
        let _ = signature_id;
        Ok(())
```
Printed by libtest while mutated:
```
test revoking_a_signature_leaves_the_party_marked_signed ... FAILED
```

#### C8 executor state change is a no-op

* occurrences checked before applying: **1** (expected 1)
* covering test: `an_executor_link_is_created_and_activated_within_one_block` (`sumchain-state --test agreement_routing`)
* anchor sha256[:16] `ea5cb758493e2966` -> replacement `86718e5fee413e57`
* verdict: **KILLED**

Anchor:
```rust
                link.state = state;
```
Replacement:
```rust
                let _ = state;
```
Printed by libtest while mutated:
```
test an_executor_link_is_created_and_activated_within_one_block ... FAILED
```

#### D1 no auto-transition at all

* occurrences checked before applying: **1** (expected 1)
* covering test: `both_signatures_in_one_block_advance_the_agreement_to_executed` (`sumchain-state --test agreement_routing`)
* anchor sha256[:16] `7c0308ce50a06ca5` -> replacement `e3b0c44298fc1c14`
* verdict: **KILLED**

Anchor:
```rust
                if agreement.is_fully_signed()
                    && agreement.status == AgreementStatus::PendingSignatures
                {
                    agreement.status = AgreementStatus::Executed;
                }
```
Replacement:
```rust
(deleted)
```
Printed by libtest while mutated:
```
test both_signatures_in_one_block_advance_the_agreement_to_executed ... FAILED
```

#### D2 auto-transition ignores the other parties

* occurrences checked before applying: **1** (expected 1)
* covering test: `without_the_first_signature_the_second_leaves_it_pending` (`sumchain-state --test agreement_routing`)
* anchor sha256[:16] `7c0308ce50a06ca5` -> replacement `a62ca3683f433793`
* verdict: **KILLED**

Anchor:
```rust
                if agreement.is_fully_signed()
                    && agreement.status == AgreementStatus::PendingSignatures
                {
                    agreement.status = AgreementStatus::Executed;
                }
```
Replacement:
```rust
                if agreement.status == AgreementStatus::PendingSignatures {
                    agreement.status = AgreementStatus::Executed;
                }
```
Printed by libtest while mutated:
```
test without_the_first_signature_the_second_leaves_it_pending ... FAILED
```

#### D3 signing does not touch updated_at

* occurrences checked before applying: **1** (expected 1)
* covering test: `the_block_timestamp_reaching_agreement_operations_is_always_zero` (`sumchain-state --test agreement_routing`)
* anchor sha256[:16] `ef94a2f791d9341b` -> replacement `271f8b789506aebe`
* verdict: **KILLED**

Anchor:
```rust
                agreement.updated_at = timestamp;

                if agreement.is_fully_signed()
```
Replacement:
```rust

                if agreement.is_fully_signed()
```
Printed by libtest while mutated:
```
test the_block_timestamp_reaching_agreement_operations_is_always_zero ... FAILED
```

#### E1 party index written before the commitment

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_640_kb_party_index_is_refused_by_the_ceiling_without_canonical_change` (`sumchain-state --test agreement_routing`)
* anchor sha256[:16] `532946573f08453b` -> replacement `ca68ea3a96c8ae04`
* verdict: **KILLED**

Anchor:
```rust
        let bytes = encode_commitment(agreement).map_err(StateError::Storage)?;
        view.put(
            cf::AGREEMENT_COMMITMENTS,
            commitment_key(&agreement.agreement_id),
            &bytes,
        )
        .map_err(StateError::Storage)?;
        for party in &agreement.parties {
            Self::v_add_to_party_index(view, &party.party_ref.as_hash(), &agreement.agreement_id)?;
        }
```
Replacement:
```rust
        for party in &agreement.parties {
            Self::v_add_to_party_index(view, &party.party_ref.as_hash(), &agreement.agreement_id)?;
        }
        let bytes = encode_commitment(agreement).map_err(StateError::Storage)?;
        view.put(
            cf::AGREEMENT_COMMITMENTS,
            commitment_key(&agreement.agreement_id),
            &bytes,
        )
        .map_err(StateError::Storage)?;
```
Printed by libtest while mutated:
```
test a_640_kb_party_index_is_refused_by_the_ceiling_without_canonical_change ... FAILED
```

#### E2 executor index written before the link

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_640_kb_executor_index_is_refused_by_the_ceiling_without_canonical_change` (`sumchain-state --test agreement_routing`)
* anchor sha256[:16] `8193637e9441ddc6` -> replacement `08a5e37d4119ebb2`
* verdict: **KILLED**

Anchor:
```rust
        let bytes = encode_executor_link(link).map_err(StateError::Storage)?;
        view.put(
            cf::AGREEMENT_EXECUTOR_LINKS,
            executor_link_key(&link.link_id),
            &bytes,
        )
        .map_err(StateError::Storage)?;
        Self::v_add_to_executor_index(view, &link.executor_contract, &link.link_id)
```
Replacement:
```rust
        let bytes = encode_executor_link(link).map_err(StateError::Storage)?;
        Self::v_add_to_executor_index(view, &link.executor_contract, &link.link_id)?;
        view.put(
            cf::AGREEMENT_EXECUTOR_LINKS,
            executor_link_key(&link.link_id),
            &bytes,
        )
        .map_err(StateError::Storage)
```
Printed by libtest while mutated:
```
test a_640_kb_executor_index_is_refused_by_the_ceiling_without_canonical_change ... FAILED
```

#### F1 commitment decode failure becomes absence

* occurrences checked before applying: **1** (expected 1)
* covering test: `corrupt_rows_error_through_dispatch_with_exactly_this_staged` (`sumchain-state --test agreement_routing`)
* anchor sha256[:16] `79e02d6b25148ba1` -> replacement `93fd1dc330102266`
* verdict: **KILLED**

Anchor:
```rust
            Some(bytes) => Ok(Some(
                decode_commitment(&bytes).map_err(StateError::Storage)?,
            )),
```
Replacement:
```rust
            Some(bytes) => Ok(decode_commitment(&bytes).ok()),
```
Printed by libtest while mutated:
```
test corrupt_rows_error_through_dispatch_with_exactly_this_staged ... FAILED
```

#### F2 signature decode failure becomes absence

* occurrences checked before applying: **1** (expected 1)
* covering test: `corrupt_rows_error_through_dispatch_with_exactly_this_staged` (`sumchain-state --test agreement_routing`)
* anchor sha256[:16] `cc6eb39ea88ed6a7` -> replacement `f67996602656ff27`
* verdict: **KILLED**

Anchor:
```rust
            Some(bytes) => Ok(Some(decode_signature(&bytes).map_err(StateError::Storage)?)),
```
Replacement:
```rust
            Some(bytes) => Ok(decode_signature(&bytes).ok()),
```
Printed by libtest while mutated:
```
test corrupt_rows_error_through_dispatch_with_exactly_this_staged ... FAILED
```

#### F3 attestation decode failure becomes absence

* occurrences checked before applying: **1** (expected 1)
* covering test: `corrupt_rows_error_through_dispatch_with_exactly_this_staged` (`sumchain-state --test agreement_routing`)
* anchor sha256[:16] `2fc35e3311d08e8c` -> replacement `e3ea410d940957c8`
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
test corrupt_rows_error_through_dispatch_with_exactly_this_staged ... FAILED
```

#### F4 ip-action decode failure becomes absence

* occurrences checked before applying: **1** (expected 1)
* covering test: `corrupt_rows_error_through_dispatch_with_exactly_this_staged` (`sumchain-state --test agreement_routing`)
* anchor sha256[:16] `0d96dc979d34ee29` -> replacement `99c9d613260d4ccc`
* verdict: **KILLED**

Anchor:
```rust
            Some(bytes) => Ok(Some(decode_ip_action(&bytes).map_err(StateError::Storage)?)),
```
Replacement:
```rust
            Some(bytes) => Ok(decode_ip_action(&bytes).ok()),
```
Printed by libtest while mutated:
```
test corrupt_rows_error_through_dispatch_with_exactly_this_staged ... FAILED
```

#### F5 executor-link decode failure becomes absence

* occurrences checked before applying: **1** (expected 1)
* covering test: `corrupt_rows_error_through_dispatch_with_exactly_this_staged` (`sumchain-state --test agreement_routing`)
* anchor sha256[:16] `5161f7be83ff0de7` -> replacement `4309c522367864b6`
* verdict: **KILLED**

Anchor:
```rust
            Some(bytes) => Ok(Some(
                decode_executor_link(&bytes).map_err(StateError::Storage)?,
            )),
```
Replacement:
```rust
            Some(bytes) => Ok(decode_executor_link(&bytes).ok()),
```
Printed by libtest while mutated:
```
test corrupt_rows_error_through_dispatch_with_exactly_this_staged ... FAILED
```

#### F6 party index decode failure becomes an empty list

* occurrences checked before applying: **1** (expected 1)
* covering test: `corrupt_rows_error_through_dispatch_with_exactly_this_staged` (`sumchain-state --test agreement_routing`)
* anchor sha256[:16] `c69207fbabcb15c1` -> replacement `4c088344c96e7bc9`
* verdict: **KILLED**

Anchor:
```rust
            Some(bytes) => decode_agreement_ids(&bytes).map_err(StateError::Storage),
```
Replacement:
```rust
            Some(bytes) => Ok(decode_agreement_ids(&bytes).unwrap_or_default()),
```
Printed by libtest while mutated:
```
test corrupt_rows_error_through_dispatch_with_exactly_this_staged ... FAILED
```

#### F7 executor index decode failure becomes an empty list

* occurrences checked before applying: **1** (expected 1)
* covering test: `corrupt_rows_error_through_dispatch_with_exactly_this_staged` (`sumchain-state --test agreement_routing`)
* anchor sha256[:16] `fcd0d1fffdf8dff5` -> replacement `0f5ab61680da76f1`
* verdict: **KILLED**

Anchor:
```rust
            Some(bytes) => decode_link_ids(&bytes).map_err(StateError::Storage),
```
Replacement:
```rust
            Some(bytes) => Ok(decode_link_ids(&bytes).unwrap_or_default()),
```
Printed by libtest while mutated:
```
test corrupt_rows_error_through_dispatch_with_exactly_this_staged ... FAILED
```

#### J4 the agreement journal starts being written

* occurrences checked before applying: **1** (expected 1)
* covering test: `the_agreement_event_journal_is_never_written` (`sumchain-state --test agreement_routing`)
* anchor sha256[:16] `e8b7d15a2bb204db` -> replacement `01216e197d492e1a`
* verdict: **KILLED**

Anchor:
```rust
        let bytes = encode_commitment(agreement).map_err(StateError::Storage)?;
        view.put(
            cf::AGREEMENT_COMMITMENTS,
            commitment_key(&agreement.agreement_id),
            &bytes,
        )
        .map_err(StateError::Storage)?;
```
Replacement:
```rust
        let bytes = encode_commitment(agreement).map_err(StateError::Storage)?;
        view.put(
            cf::AGREEMENT_COMMITMENTS,
            commitment_key(&agreement.agreement_id),
            &bytes,
        )
        .map_err(StateError::Storage)?;
        view.put(
            cf::AGREEMENT_EVENTS,
            commitment_key(&agreement.agreement_id),
            b"committed",
        )
        .map_err(StateError::Storage)?;
```
Printed by libtest while mutated:
```
test the_agreement_event_journal_is_never_written ... FAILED
```

#### J5 signing refuses a party outside the agreement

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_signature_for_a_party_outside_the_agreement_is_still_recorded` (`sumchain-state --test agreement_routing`)
* anchor sha256[:16] `63edd52290f2d9a3` -> replacement `d4ace9d4919a58be`
* verdict: **KILLED**

Anchor:
```rust
                for party in &mut agreement.parties {
                    if party.party_ref.as_hash() == *party_ref_hash {
                        party.signed = true;
                        party.signed_at = Some(timestamp);
                    }
                }
```
Replacement:
```rust
                let mut matched = false;
                for party in &mut agreement.parties {
                    if party.party_ref.as_hash() == *party_ref_hash {
                        party.signed = true;
                        party.signed_at = Some(timestamp);
                        matched = true;
                    }
                }
                if !matched {
                    return Err(not_found("Party", party_ref_hash));
                }
```
Printed by libtest while mutated:
```
test a_signature_for_a_party_outside_the_agreement_is_still_recorded ... FAILED
```

#### K1 party index replaces instead of appending

* occurrences checked before applying: **1** (expected 1)
* covering test: `two_agreements_for_one_party_accumulate_in_the_index` (`sumchain-state --test agreement_routing`)
* anchor sha256[:16] `fc5f3a684631f4ed` -> replacement `dbec8a9ae84acf58`
* verdict: **KILLED**

Anchor:
```rust
        ids.push(*agreement_id);
```
Replacement:
```rust
        ids.clear();
        ids.push(*agreement_id);
```
Printed by libtest while mutated:
```
test two_agreements_for_one_party_accumulate_in_the_index ... FAILED
```

#### K2 executor index replaces instead of appending

* occurrences checked before applying: **1** (expected 1)
* covering test: `two_links_for_one_executor_accumulate_in_the_index` (`sumchain-state --test agreement_routing`)
* anchor sha256[:16] `6d2aa91e6e78baea` -> replacement `92f6b39160b76800`
* verdict: **KILLED**

Anchor:
```rust
        ids.push(*link_id);
```
Replacement:
```rust
        ids.clear();
        ids.push(*link_id);
```
Printed by libtest while mutated:
```
test two_links_for_one_executor_accumulate_in_the_index ... FAILED
```

#### K3 agreement status update is a no-op

* occurrences checked before applying: **1** (expected 1)
* covering test: `any_sender_can_terminate_void_and_revoke_anything` (`sumchain-state --test agreement_routing`)
* anchor sha256[:16] `823496886aa499cf` -> replacement `14b8a4aeb7f639f5`
* verdict: **KILLED**

Anchor:
```rust
                agreement.status = status;
                agreement.updated_at = timestamp;
```
Replacement:
```rust
                let _ = (status, timestamp);
```
Printed by libtest while mutated:
```
test any_sender_can_terminate_void_and_revoke_anything ... FAILED
```

#### K4 attestation status update is a no-op

* occurrences checked before applying: **1** (expected 1)
* covering test: `only_the_issuer_may_revoke_or_update_its_own_attestation` (`sumchain-state --test agreement_routing`)
* anchor sha256[:16] `f464d577fd4046f6` -> replacement `bd991f9bb3edff0a`
* verdict: **KILLED**

Anchor:
```rust
                att.status = status;
```
Replacement:
```rust
                let _ = status;
```
Printed by libtest while mutated:
```
test only_the_issuer_may_revoke_or_update_its_own_attestation ... FAILED
```

#### K5 ip action status update is a no-op

* occurrences checked before applying: **1** (expected 1)
* covering test: `any_sender_can_terminate_void_and_revoke_anything` (`sumchain-state --test agreement_routing`)
* anchor sha256[:16] `d962080ac64b47dd` -> replacement `bd991f9bb3edff0a`
* verdict: **KILLED**

Anchor:
```rust
                action.status = status;
```
Replacement:
```rust
                let _ = status;
```
Printed by libtest while mutated:
```
test any_sender_can_terminate_void_and_revoke_anything ... FAILED
```

### `crates/state/src/agreement_executor.rs`


#### J1 signing is bound to the sender

* occurrences checked before applying: **1** (expected 1)
* covering test: `any_sender_can_sign_on_behalf_of_any_party` (`sumchain-state --test agreement_routing`)
* anchor sha256[:16] `db51858ea0bf226f` -> replacement `6763de4d9cd8218d`
* verdict: **KILLED**

Anchor:
```rust
                if Self::v_signature_exists(view, &signature.signature_id)? {
                    return Ok(AgreementExecutionResult::failure("Signature already exists"));
                }
```
Replacement:
```rust
                if Self::v_signature_exists(view, &signature.signature_id)? {
                    return Ok(AgreementExecutionResult::failure("Signature already exists"));
                }

                if signature.party_ref.as_hash()[..20] != *sender.as_ref() {
                    return Ok(AgreementExecutionResult::failure("Signer is not the party"));
                }
```
Printed by libtest while mutated:
```
test any_sender_can_sign_on_behalf_of_any_party ... FAILED
```

#### J2 AddParty/RemoveParty refuse instead of doing nothing

* occurrences checked before applying: **1** (expected 1)
* covering test: `add_party_and_remove_party_charge_a_fee_and_do_nothing` (`sumchain-state --test agreement_routing`)
* anchor sha256[:16] `55628441e5255be3` -> replacement `e0c4362c842ec5ca`
* verdict: **KILLED**

Anchor:
```rust
            AgreementOperation::AddParty | AgreementOperation::RemoveParty => {
                // These would require updating agreement parties
```
Replacement:
```rust
            AgreementOperation::AddParty | AgreementOperation::RemoveParty => {
                return Ok(AgreementExecutionResult::failure("Not implemented"));
                #[allow(unreachable_code)]
```
Printed by libtest while mutated:
```
test add_party_and_remove_party_charge_a_fee_and_do_nothing ... FAILED
```

#### J3 termination requires the sender to be a party

* occurrences checked before applying: **1** (expected 1)
* covering test: `any_sender_can_terminate_void_and_revoke_anything` (`sumchain-state --test agreement_routing`)
* anchor sha256[:16] `e3b57ffc41d5add1` -> replacement `e3b2062e28961d45`
* verdict: **KILLED**

Anchor:
```rust
                if Self::v_get_agreement(view, &d.agreement_id)?.is_none() {
                    return Ok(AgreementExecutionResult::failure("Agreement not found"));
                }

                let new_status = if data.operation == AgreementOperation::TerminateAgreement {
```
Replacement:
```rust
                let existing = match Self::v_get_agreement(view, &d.agreement_id)? {
                    Some(a) => a,
                    None => return Ok(AgreementExecutionResult::failure("Agreement not found")),
                };
                if !existing
                    .parties
                    .iter()
                    .any(|p| p.party_ref.as_hash()[..20] == *sender.as_ref())
                {
                    return Ok(AgreementExecutionResult::failure("Sender is not a party"));
                }

                let new_status = if data.operation == AgreementOperation::TerminateAgreement {
```
Printed by libtest while mutated:
```
test any_sender_can_terminate_void_and_revoke_anything ... FAILED
```

### `crates/storage/src/agreement_store.rs`


#### G1 commitment key truncated

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_commitment_row_is_bincode_at_the_agreement_id_key_and_indexes_every_party` (`sumchain-storage --test agreement_codec_parity`)
* anchor sha256[:16] `59901093426b30e3` -> replacement `592ee702a9504675`
* verdict: **KILLED**

Anchor:
```rust
pub fn commitment_key(agreement_id: &AgreementId) -> &[u8] {
    agreement_id
}
```
Replacement:
```rust
pub fn commitment_key(agreement_id: &AgreementId) -> &[u8] {
    &agreement_id[..16]
}
```
Printed by libtest while mutated:
```
test a_commitment_row_is_bincode_at_the_agreement_id_key_and_indexes_every_party ... FAILED
```

#### G2 party index key truncated

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_commitment_row_is_bincode_at_the_agreement_id_key_and_indexes_every_party` (`sumchain-storage --test agreement_codec_parity`)
* anchor sha256[:16] `3844baf459e0fced` -> replacement `8de6539fd1ddca86`
* verdict: **KILLED**

Anchor:
```rust
pub fn party_index_key(party_ref_hash: &[u8; 32]) -> &[u8] {
    party_ref_hash
}
```
Replacement:
```rust
pub fn party_index_key(party_ref_hash: &[u8; 32]) -> &[u8] {
    &party_ref_hash[..16]
}
```
Printed by libtest while mutated:
```
test a_commitment_row_is_bincode_at_the_agreement_id_key_and_indexes_every_party ... FAILED
```

#### G3 signature key truncated

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_signature_row_is_bincode_at_the_signature_id_key` (`sumchain-storage --test agreement_codec_parity`)
* anchor sha256[:16] `58aa99be7d9d456e` -> replacement `a75e212975ba4987`
* verdict: **KILLED**

Anchor:
```rust
pub fn signature_key(signature_id: &SignatureId) -> &[u8] {
    signature_id
}
```
Replacement:
```rust
pub fn signature_key(signature_id: &SignatureId) -> &[u8] {
    &signature_id[..16]
}
```
Printed by libtest while mutated:
```
test a_signature_row_is_bincode_at_the_signature_id_key ... FAILED
```

#### G4 attestation key truncated

* occurrences checked before applying: **1** (expected 1)
* covering test: `an_attestation_row_is_bincode_at_the_attestation_id_key` (`sumchain-storage --test agreement_codec_parity`)
* anchor sha256[:16] `6314252d177dde16` -> replacement `6e529d1c189cd2aa`
* verdict: **KILLED**

Anchor:
```rust
pub fn attestation_key(attestation_id: &AttestationId) -> &[u8] {
    attestation_id
}
```
Replacement:
```rust
pub fn attestation_key(attestation_id: &AttestationId) -> &[u8] {
    &attestation_id[..16]
}
```
Printed by libtest while mutated:
```
test an_attestation_row_is_bincode_at_the_attestation_id_key ... FAILED
```

#### G5 ip-action key truncated

* occurrences checked before applying: **1** (expected 1)
* covering test: `an_ip_action_row_is_bincode_at_the_action_id_key` (`sumchain-storage --test agreement_codec_parity`)
* anchor sha256[:16] `cf390e464e0bd306` -> replacement `d870fa9d87ecdbe1`
* verdict: **KILLED**

Anchor:
```rust
pub fn ip_action_key(action_id: &IpAssetId) -> &[u8] {
    action_id
}
```
Replacement:
```rust
pub fn ip_action_key(action_id: &IpAssetId) -> &[u8] {
    &action_id[..16]
}
```
Printed by libtest while mutated:
```
test an_ip_action_row_is_bincode_at_the_action_id_key ... FAILED
```

#### G6 executor link key truncated

* occurrences checked before applying: **1** (expected 1)
* covering test: `an_executor_link_row_is_bincode_at_the_link_id_key_and_indexes_its_contract` (`sumchain-storage --test agreement_codec_parity`)
* anchor sha256[:16] `0646d14a77f7b6dc` -> replacement `4951b75fa65d3a98`
* verdict: **KILLED**

Anchor:
```rust
pub fn executor_link_key(link_id: &ExecutorLinkId) -> &[u8] {
    link_id
}
```
Replacement:
```rust
pub fn executor_link_key(link_id: &ExecutorLinkId) -> &[u8] {
    &link_id[..16]
}
```
Printed by libtest while mutated:
```
test an_executor_link_row_is_bincode_at_the_link_id_key_and_indexes_its_contract ... FAILED
```

#### G7 executor index key truncated

* occurrences checked before applying: **1** (expected 1)
* covering test: `an_executor_link_row_is_bincode_at_the_link_id_key_and_indexes_its_contract` (`sumchain-storage --test agreement_codec_parity`)
* anchor sha256[:16] `e8cedd16b99911e0` -> replacement `482c4e8711a533af`
* verdict: **KILLED**

Anchor:
```rust
pub fn executor_index_key(executor: &Address) -> &[u8] {
    executor.as_ref()
}
```
Replacement:
```rust
pub fn executor_index_key(executor: &Address) -> &[u8] {
    &executor.as_ref()[..8]
}
```
Printed by libtest while mutated:
```
test an_executor_link_row_is_bincode_at_the_link_id_key_and_indexes_its_contract ... FAILED
```

#### G8 proof key truncated

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_proof_row_is_bincode_at_the_proof_id_key_and_writes_no_index` (`sumchain-storage --test agreement_codec_parity`)
* anchor sha256[:16] `5af8daf44557c6e1` -> replacement `476664362dc4e00a`
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
```

#### H1 agreement-id list encodes only the first

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_second_agreement_for_one_party_appends_to_the_same_list` (`sumchain-storage --test agreement_codec_parity`)
* anchor sha256[:16] `d5903a11e21e8838` -> replacement `2e4e39904f0acd44`
* verdict: **KILLED**

Anchor:
```rust
pub fn encode_agreement_ids(ids: &[AgreementId]) -> Result<Vec<u8>> {
    bincode::serialize(ids)
```
Replacement:
```rust
pub fn encode_agreement_ids(ids: &[AgreementId]) -> Result<Vec<u8>> {
    bincode::serialize(&ids[..ids.len().min(1)])
```
Printed by libtest while mutated:
```
test a_second_agreement_for_one_party_appends_to_the_same_list ... FAILED
```

#### H2 link-id list encodes only the first

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_second_link_for_one_contract_appends_to_the_same_list` (`sumchain-storage --test agreement_codec_parity`)
* anchor sha256[:16] `1f7a6a8c9202507b` -> replacement `03ac138992818647`
* verdict: **KILLED**

Anchor:
```rust
pub fn encode_link_ids(ids: &[ExecutorLinkId]) -> Result<Vec<u8>> {
    bincode::serialize(ids)
```
Replacement:
```rust
pub fn encode_link_ids(ids: &[ExecutorLinkId]) -> Result<Vec<u8>> {
    bincode::serialize(&ids[..ids.len().min(1)])
```
Printed by libtest while mutated:
```
test a_second_link_for_one_contract_appends_to_the_same_list ... FAILED
```

#### H3 commitment encodes only its id

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_commitment_row_is_bincode_at_the_agreement_id_key_and_indexes_every_party` (`sumchain-storage --test agreement_codec_parity`)
* anchor sha256[:16] `28328f1fbe03f729` -> replacement `b248508f40e40322`
* verdict: **KILLED**

Anchor:
```rust
pub fn encode_commitment(c: &AgreementCommitment) -> Result<Vec<u8>> {
    bincode::serialize(c)
```
Replacement:
```rust
pub fn encode_commitment(c: &AgreementCommitment) -> Result<Vec<u8>> {
    bincode::serialize(&c.agreement_id)
```
Printed by libtest while mutated:
```
test a_commitment_row_is_bincode_at_the_agreement_id_key_and_indexes_every_party ... FAILED
```

#### H4 signature encodes only its id

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_signature_row_is_bincode_at_the_signature_id_key` (`sumchain-storage --test agreement_codec_parity`)
* anchor sha256[:16] `b4597ccb8733883d` -> replacement `149908fdf55263ca`
* verdict: **KILLED**

Anchor:
```rust
pub fn encode_signature(s: &PartySignature) -> Result<Vec<u8>> {
    bincode::serialize(s)
```
Replacement:
```rust
pub fn encode_signature(s: &PartySignature) -> Result<Vec<u8>> {
    bincode::serialize(&s.signature_id)
```
Printed by libtest while mutated:
```
test a_signature_row_is_bincode_at_the_signature_id_key ... FAILED
```

#### H5 proof encodes only its id

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_proof_row_is_bincode_at_the_proof_id_key_and_writes_no_index` (`sumchain-storage --test agreement_codec_parity`)
* anchor sha256[:16] `2045b0505419b43f` -> replacement `c8ccf1e5f9c66233`
* verdict: **KILLED**

Anchor:
```rust
pub fn encode_proof(p: &AgreementProofEnvelope) -> Result<Vec<u8>> {
    bincode::serialize(p)
```
Replacement:
```rust
pub fn encode_proof(p: &AgreementProofEnvelope) -> Result<Vec<u8>> {
    bincode::serialize(&p.proof_id)
```
Printed by libtest while mutated:
```
test a_proof_row_is_bincode_at_the_proof_id_key_and_writes_no_index ... FAILED
```

#### H6 agreement-id list decode swallows corruption

* occurrences checked before applying: **1** (expected 1)
* covering test: `corrupt_rows_error_through_dispatch_with_exactly_this_staged` (`sumchain-state --test agreement_routing`)
* anchor sha256[:16] `46bfdca34df35920` -> replacement `84fbb67548042116`
* verdict: **KILLED**

Anchor:
```rust
pub fn decode_agreement_ids(bytes: &[u8]) -> Result<Vec<AgreementId>> {
    bincode::deserialize(bytes).map_err(|e| StorageError::Serialization(e.to_string()))
```
Replacement:
```rust
pub fn decode_agreement_ids(bytes: &[u8]) -> Result<Vec<AgreementId>> {
    Ok(bincode::deserialize(bytes).unwrap_or_default())
```
Printed by libtest while mutated:
```
test corrupt_rows_error_through_dispatch_with_exactly_this_staged ... FAILED
```

#### H7 link-id list decode swallows corruption

* occurrences checked before applying: **1** (expected 1)
* covering test: `corrupt_rows_error_through_dispatch_with_exactly_this_staged` (`sumchain-state --test agreement_routing`)
* anchor sha256[:16] `393dd749335d5b34` -> replacement `f4362bd8367e5bb9`
* verdict: **KILLED**

Anchor:
```rust
pub fn decode_link_ids(bytes: &[u8]) -> Result<Vec<ExecutorLinkId>> {
    bincode::deserialize(bytes).map_err(|e| StorageError::Serialization(e.to_string()))
```
Replacement:
```rust
pub fn decode_link_ids(bytes: &[u8]) -> Result<Vec<ExecutorLinkId>> {
    Ok(bincode::deserialize(bytes).unwrap_or_default())
```
Printed by libtest while mutated:
```
test corrupt_rows_error_through_dispatch_with_exactly_this_staged ... FAILED
```

### `crates/state/src/executor.rs`


#### I1 live arm passes the real block timestamp

* occurrences checked before applying: **1** (expected 1)
* covering test: `the_block_timestamp_reaching_agreement_operations_is_always_zero` (`sumchain-state --test agreement_routing`)
* anchor sha256[:16] `82f4c920f56b473f` -> replacement `4a5eb26c0740996e`
* verdict: **KILLED**

Anchor:
```rust
                        let result = AgreementExecutor::execute(
                            view,
                            &v2_tx.from,
                            &agreement_data,
                            proposer,
                            v2_tx.fee,
                            block_height,
                            0, // block_timestamp placeholder
```
Replacement:
```rust
                        let result = AgreementExecutor::execute(
                            view,
                            &v2_tx.from,
                            &agreement_data,
                            proposer,
                            v2_tx.fee,
                            block_height,
                            block_timestamp, // block_timestamp placeholder
```
Printed by libtest while mutated:
```
test the_block_timestamp_reaching_agreement_operations_is_always_zero ... FAILED
```

#### I2 v2 arm passes the real block timestamp

* occurrences checked before applying: **1** (expected 1)
* covering test: `the_v2_dispatch_surface_also_stages_agreements` (`sumchain-state --test agreement_routing`)
* anchor sha256[:16] `9991783c6ed0a1de` -> replacement `a0f55b713d0529c0`
* verdict: **KILLED**

Anchor:
```rust
                let result = AgreementExecutor::execute(
                    view,
                    &tx.from,
                    agreement_data,
                    proposer,
                    tx.fee,
                    block_height,
                    0, // block_timestamp placeholder
```
Replacement:
```rust
                let result = AgreementExecutor::execute(
                    view,
                    &tx.from,
                    agreement_data,
                    proposer,
                    tx.fee,
                    block_height,
                    block_timestamp, // block_timestamp placeholder
```
Printed by libtest while mutated:
```
test the_v2_dispatch_surface_also_stages_agreements ... FAILED
```

#### I3 live arm reports a neighbouring status code

* occurrences checked before applying: **1** (expected 1)
* covering test: `without_the_commitment_the_same_signature_is_refused` (`sumchain-state --test agreement_routing`)
* anchor sha256[:16] `e38e6d92f84cc902` -> replacement `e95e11f5647bd54d`
* verdict: **KILLED**

Anchor:
```rust
                            Ok(TxExecutionResult {
                                tx_hash,
                                status: TxStatus::Failed(11), // Agreement operation failed
```
Replacement:
```rust
                            Ok(TxExecutionResult {
                                tx_hash,
                                status: TxStatus::Failed(12), // Agreement operation failed
```
Printed by libtest while mutated:
```
test without_the_commitment_the_same_signature_is_refused ... FAILED
```

#### I4 v2 arm reports a neighbouring status code

* occurrences checked before applying: **1** (expected 1)
* covering test: `the_v2_dispatch_surface_also_stages_agreements` (`sumchain-state --test agreement_routing`)
* anchor sha256[:16] `bb4379f76064422e` -> replacement `0485353da86e1085`
* verdict: **KILLED**

Anchor:
```rust
                    Ok(TxExecutionResult {
                        tx_hash,
                        status: TxStatus::Failed(11), // Agreement operation failed
```
Replacement:
```rust
                    Ok(TxExecutionResult {
                        tx_hash,
                        status: TxStatus::Failed(12), // Agreement operation failed
```
Printed by libtest while mutated:
```
test the_v2_dispatch_surface_also_stages_agreements ... FAILED
```

## Totals and post-run hashes

```
=== totals ===
  killed: 62
  declared: 62   scored: 62

=== post-run hashes (authoritative) ===
  MATCH   ea1a65df4b5ed9ff3882102a192fce5b9be7ce2e02116897028ca1d2453447ce  crates/state/src/agreement_view.rs
  MATCH   b010e0a47c287144a3dba2b1210df11a935a40bdbe561ce901e9a376e90441f9  crates/state/src/agreement_executor.rs
  MATCH   de8f6a5bbfe648612744b1e71bfdc5db159ed8bb9d88dc4ee4236f2926a97854  crates/state/src/executor.rs
  MATCH   2443cc962f2e6337c3dc996a1888a11b6931305a1e69d74806ca2c0d53d58e21  crates/storage/src/agreement_store.rs
  all four byte-identical to pre-run: True

=== anchors resolve exactly once again ===
  62/62
```
