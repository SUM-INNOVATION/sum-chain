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

## Status by subsystem

| subsystem | commit | inventory |
|---|---|---|
| PolicyAccount | `855ec009` | in the commit message |
| Messaging + sponsored registration | `e293b03a` | in the commit message |
| Tax | `1c5494c` | in the commit message |
| Employment (SRC-88X) | `623e41f` (was `04eb5bc`) | in the commit message |
| Legal (SRC-85X) | `ddc4985` (was `026447f`) | in the commit message |
| Finance (SRC-89X) | `d570469` (was `0706862`) | in the commit message |
| Agreement (SRC-84X) | `2249ca8` | transcribed in full below |
| Property (SRC-86X) | this wave | transcribed in full below |
| Healthcare (SRC-87X) | this wave | transcribed in full below |
| NFT (SUM-721) | this wave | transcribed in full below |

Agreement, property, healthcare and NFT are transcribed here. The six earlier
inventories are recorded in their own commit messages and have not been copied
into this file; a pointer is not a transcription, and listing them here from
memory would be worse than listing them not at all.

Employment, legal and finance were reviewed to an earlier and weaker bar than
this wave, and their rows above carry the SHA they now have on this branch, not
the SHA of the parallel branch they were authored on. Three gaps in that earlier
review are closed by test-only additions on this branch: employment had no
close/reopen restart-parity test, and none of the three had a publication
byte-contract test of the kind property carries. One gap is NOT closed and is
recorded here rather than implied away: neither employment nor legal committed a
per-mutation battery document. Their commit messages report 52/52 and 56/56
killed, but that record is not auditable in the tree, and this branch does not
make it so. Finance's battery is at `docs/lane-a/FINANCE-MUTATION-BATTERY.md`.

## Agreement (SRC-84X)

Eleven items, grouped as the reviewer framed them.

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

Thirteen items, grouped as the reviewer framed them.

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
## Healthcare (SRC-87X)

Twenty-two items. Healthcare is the subsystem where an authorization defect is
least tolerable, and it has the weakest authorization in the lane so far: the
consent lifecycle can be taken over by any sender, and a prescription can be
filled by anyone at all.

### Unrestricted allocation from untrusted input

SEVEN accumulating structures, not two. Five are index families whose values are
`Vec` lists; two accumulate INSIDE a primary row, so the buffer that gets built
is the entire record. Every one serializes its whole contents before `view.put`
## NFT (SUM-721)

Sixteen items. Every one is inherited, reproduced deliberately, and pinned by
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
