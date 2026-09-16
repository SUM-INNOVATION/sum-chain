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
| Agreement (SRC-84X) | this commit | transcribed in full below |

Only agreement is transcribed here so far. The earlier inventories are recorded
in their own commit messages and have not been copied into this file; a pointer
is not a transcription, and listing them here from memory would be worse than
listing them not at all.

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
