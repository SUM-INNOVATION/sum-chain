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
| Employment | `04eb5bc` (parallel) | in the commit message |
| Legal | `026447f` (parallel) | in the commit message |
| Finance | `0706862` (parallel) | in the commit message |
| Agreement (SRC-84X) | `2249ca8` | transcribed in full below |
| Property (SRC-86X) | this commit | transcribed in full below |

Agreement and property are transcribed here. The earlier inventories are
recorded in their own commit messages and have not been copied into this file; a
pointer is not a transcription, and listing them here from memory would be worse
than listing them not at all.

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
