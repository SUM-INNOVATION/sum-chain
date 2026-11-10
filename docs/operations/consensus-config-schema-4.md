# Consensus configuration schema 4: enablement, migration, abort points, forward recovery

> **Status:** code enablement (draft). No release, database migration, gate
> height or activation is part of the change that adds this document.

Schema 4 of the local consensus configuration
(`crates/consensus/src/consensus_config`) is schema 3 plus exactly four
optional fields, each meaning "the behaviour that existed before" when absent:

| Id | Field | Effect from its height |
|---|---|---|
| `0x1044` | `archive_unbonding_own_challenges_enabled_from_height` | `BeginUnstake` counts only the sender's own open storage challenges |
| `0x1045` | `por_attested_targets_enabled_from_height` | a storage challenge targets only an archive that attested the chunk in the file's latest assignment epoch |
| `0x1046` | `strict_transaction_signatures_enabled_from_height` | transaction signatures are checked with the strict Ed25519 rule |
| `0x1047` | `staking_submit_evidence_unsupported_enabled_from_height` | the legacy staking `SubmitEvidence` operation is refused |

This binary writes schema 4 (`PRODUCTION`: reads 1, 2, 3 and 4, writes 4).
That freezes schema 4: its registry and encoding never change again, and a
later field goes into schema 5. The encoding is unchanged (`CCFGv1`), and so is
the record layout. The encoding is pinned by golden vectors in
`crates/consensus/tests/consensus_config.rs` (`schema_4_golden_vectors`, and a
byte-for-byte comparison with the frozen schema-3 encoding); the frozen
schema-1, schema-2 and schema-3 vectors are unchanged. The migration, the
pre-start revert and the refusals below are tested in
`crates/consensus/tests/consensus_config_schema4.rs`,
`crates/node/tests/acknowledge_consensus_config_guard.rs`,
`crates/node/tests/consensus_config_schema_crash.rs` (each write killed with
SIGKILL) and the node's boot tests.

The record stays a local, unverified baseline. Nothing here is exchanged with
peers or authorizes anything on the network.

## 1. Installing the binary changes no rule

- **The four gates are unset** in every tracked genesis and template, in
  `ChainParams::default()` and in the local-testnet generator. A node running
  this binary with them unset executes exactly what it executed before.
- **The upgrade is same-window.** The activation and protocol digests fold
  every declared gate name, set or not. A release that declares a name the
  running release does not declare moves both digests, and peers compare the
  protocol digest when they connect: the two releases refuse each other. Stop
  every validator, and every other node that follows the chain, install, and
  start them together. Measure the digests of the candidate on a
  production-shaped genesis before the window.
- **Fresh data directory:** the node records schema 4 directly.
- **Data directory recorded in schema 1, 2 or 3:** the node runs it exactly as
  it stands. It is compared in its own schema, never re-encoded at start, and
  the start reports `Unchanged`. Every start logs a WARN that a schema
  transition is available, with both commitments.
- **`chain_getConsensusConfig` on such a node** reports the record's schema and
  commitment, and `matches_baseline: true`. Its `running_commitment` is the
  schema-4 value, so it differs from `commitment` until the record moves.

## 2. The window

On each node, in one window on every node:

1. stop the node;
2. `sumchain check-finality-record --data-dir <dir>` with the new binary
   (read-only; exit 2 means the start would refuse);
3. take a copy of the data directory, **for forensics only** (section 5);
4. install the new binary;
5. `sumchain acknowledge-consensus-config-schema --data-dir <dir> --show`;
6. `sumchain acknowledge-consensus-config-schema --data-dir <dir> --old <recorded> --new <re-encoded>`;
7. start.

Then the agreement checks on every node: heads, hashes and state roots at a
common height, peer count, and the consensus-configuration report below.

- **`--show`** opens the database read-only, writes nothing, and prints the
  move this binary would make, with `--old` and `--new` exactly as the move
  takes them. On a database already in schema 4 it says there is nothing to
  move. `--old` is the recorded commitment; `--new` is a pure function of the
  record, so nodes that record the same commitment print the same `--new`.
- **The move** re-encodes the recorded rules, adding every field the newer
  schemas add as absent, and changes no rule. It consults no genesis. It keeps
  the old encoding in the append-only history, which every later start
  re-verifies. It writes exactly two rows, the record and one transition, in
  one durable batch: killed before the commit, the database is exactly the old
  one and the command can simply be run again; killed after it, the database
  is exactly the moved one.
- **The move refuses, and writes nothing,** on:
  - anything but both exact commitments (the refusal of a wrong `--new` names
    the right one);
  - a database already in schema 4;
  - a damaged record or history;
  - a record of a schema this binary does not implement ("written by a newer
    binary");
  - a database held by a running node.
- **After the move,** the next start with the same genesis reports `Unchanged`
  against the moved record. `chain_getConsensusConfig` then reports schema 4,
  `commitment` equal to `--new`, `running_commitment` equal to `commitment`,
  `matches_baseline: true`, and a history ending in `schema-transition`.
- **A record that disagrees with the genesis** refuses start before the move
  and after it, naming the same fields and `acknowledge-consensus-config`.
  That acknowledgement is a separate decision and not part of this window.

## 3. Abort points

An abort returns every node to the release it ran, at the agreed height and
state. Abort on every node together; the stopped tips must be equal before
any node starts. **The abort window closes at the first normal start attempt
of the new binary on either node**, whatever that start then does: a start
that imports nothing, or that is refused by a later check, closes it as much
as one that runs. The pair then goes forward (section 5).

| Abort point | The database | Return to the running release |
|---|---|---|
| Before installing | unchanged | start the running release |
| After installing, before the move | unchanged: `check-finality-record` and `--show` are read-only, and the new binary has not started | reinstall the running release and start it |
| After the move, before any normal start attempt on either node | the moved record, which the running release refuses ("written by a newer binary"); no start marker | the pair-wide check below on both nodes, then the pre-start revert on both, then reinstall the running release and start it |
| After a normal start attempt of the new binary on either node | that node holds a start marker written at the move | no abort back for the pair; forward recovery only (section 5) |

**The start marker.** Every normal start writes a marker (`cf::META`
`node/start-marker/v1`) as its first write, immediately after the database is
opened and before the journal format check, the messaging backfill, the
activation-height record, the configuration baseline, genesis initialization
and the node key. It records the attempt count, the configuration record's
transition count and commitment as read at that start, and the chain head. If
it cannot be written the start refuses with nothing else written. The read-only
commands (`--version`, both `--show`s, `check-finality-record`,
`inspect-v2-rows`, `info`, `export-registered-keys`) never write it; neither do
the move and the revert.

**Masking the unit.** The service unit stays masked (or disabled) on every
node from the stop until the operator's own start, so no auto-start,
restart policy or hand start can close the window unnoticed.

**The pair-wide check (before any revert).** On both nodes, stopped,
read-only:

1. `revert-consensus-config-schema --show` prints the start marker (`none`),
   the head, and the move it would undo;
2. the head height and hash equal the agreed tip, and are equal on both nodes;
3. each database's full key/value digest equals the digest taken right
   after that node's move (this also catches a start of any other
   binary, and any other command run in between);
4. the service unit stayed masked or inactive since the stop (no unit start
   in the journal, `ActiveEnterTimestamp` and `NRestarts` unchanged);
5. the operator's own record shows no start issued to either node since the
   move.

Abort-3 only if all five pass on **both** nodes. If anything fails on either
node, **both go forward**. If a revert succeeds on one node and fails on the
other, re-run the move on the reverted node (it is offered again) and go
forward with both. Reverting only one node would put the two validators on
binaries that refuse each other by digest, and the chain would halt.

**The pre-start revert.** With the new binary, on the stopped node:

```
sumchain revert-consensus-config-schema --data-dir <dir> --show
sumchain revert-consensus-config-schema --data-dir <dir> --old <moved> --new <restored>
```

- **`--show`** is read-only and prints the start marker, the head, and the
  revert with `--old` (the moved commitment, the move's `--new`) and `--new`
  (the commitment restored, the move's `--old`), or why no revert is
  available.
- **The revert** writes back exactly the record the move replaced, which the
  move kept in its transition, and removes that transition, in one durable
  batch. Every row of every column family is then byte for byte what it was
  before the move. `acknowledge-consensus-config-schema --show` offers the
  same move again.
- **It touches no block, no state and no other row,** the start marker
  included. It is not a restore of any copy and it rewinds nothing.
- **It is refused, and writes nothing,** when a start marker written at the
  move exists (a normal start was attempted, imported or not, refused or not);
  when the marker cannot be read or disagrees with the history (an uncertain
  migration state); unless the last recorded change is the move into the
  schema this binary writes and the chain head is exactly the height the move
  was made at, with no block above it in the block-height index. It also
  refuses wrong commitments, a damaged or unknown record, a second run, and a
  database held by a running node. Killed before its commit, the database is
  exactly the moved one; after it, exactly the old one.
- **A rewind does not reopen it.** The decision rests on the marker, which no
  block, journal or chain position carries. `sumchain rollback` keeps the
  marker and the configuration rows (it verifies this before and after, and
  refuses while a move awaits its first start or its revert); `sumchain
  restore` refuses a backup that would clear the marker or change the record's
  history. Neither has a bypass flag.

**`rollback` and `restore` are not part of this procedure**, before, during or
after the window. The window's data copy is for forensics only. The older
stage-1 rollback sections (`stage1-native-runbook.md` §5.3,
`stage1-rollout-runbook.md`) and the production checklist's "restore the
validator's data directory from a snapshot" paragraph do not apply to a moved
node; marking them superseded is a separate docs change.

## 4. Scheduling a gate (after the move; a coordinated decision)

Not part of this stage. For reference:

- **Move first.** Before the move, a genesis that sets one of the four gates
  refuses start, naming the exact `acknowledge-consensus-config-schema --old …
  --new …` command, and the configuration record is not rewritten. The
  activation-height check runs earlier in the start and records the new
  future heights in the node's activation record; restoring the previous
  genesis is then an ordinary, permitted future reschedule.
- **After the move,** a gate at a height the chain has not reached is recorded
  at start as a gate reschedule of exactly that field.
- **The peer-declaration deadline at or below the gate.** Each of the four is a
  remediation gate: genesis validation refuses it without
  `peer_protocol_declaration_required_from_height` at or below it.
- **Not in the past.** A height at or below the node's current height cannot
  be scheduled. Once the chain reaches a gate, it can neither move nor be
  unset.
- **Identical everywhere, in one window.** The heights enter the activation and
  protocol digests; nodes with different values do not interoperate.

## 5. After the first start attempt: forward recovery only

- **No rewind and no restore.** No step of recovery rewinds the chain or writes
  a data copy back over accepted blocks. The copy taken in the window is for
  forensics only.
- **Recovery is a compatible binary:** stop the node, install it, start, and
  repeat the agreement checks. The start must report `Unchanged` with the same
  commitment.
- **Compatible** means all of:
  - it **writes schema 4**, and reads schema 4 and keeps reading schemas 1, 2
    and 3: a moved node's history holds schema transitions whose kept
    encodings are older schemas, and every start re-verifies them;
  - its schema-4 registry is this one: the same four ids, names and types,
    encoding byte for byte as the schema-4 golden vectors;
  - it computes the same consensus-configuration commitment from the same
    genesis: the same rule codes, parameters and compiled consensus constants
    (otherwise the start refuses and names `acknowledge-consensus-config`);
  - it declares the same activation-gate names, so its activation and protocol
    digests equal the other validators';
  - it accepts the database's other formats (the application-journal format,
    the finality and certified-finality records, and the start marker).
- **What a fixed release must preserve:** schema 4 as the written schema and
  in `reads` for good, `SCHEMA_4_ADDED` unchanged, the four gate names
  unchanged, and every consensus rule and constant unchanged unless the change
  is itself a coordinated, acknowledged upgrade.
- **A release that writes schema 5 is not a recovery binary.** It is a new
  same-window upgrade with its own window: its running commitment differs, so
  under B2 (below) it declares a different handshake digest and is refused by
  schema-4 peers.
- **Not compatible:** any release that reads only schemas up to 3, the
  deployed one included. It refuses the moved record ("written by a newer
  binary") and rewrites nothing in it, but its activation-height check runs
  first and rewrites the activation record without the names it does not
  declare (`0x1046` and `0x1047` for the deployed release). A later start of
  this binary accepts the missing names while those gates are unset, and
  restores a name whose gate has passed when the verified schema-4 record
  holds the same height. Do not start such a release on a moved node.
- **After a gate height is written:** a binary without the gate does not
  enforce it. Do not return such a binary to service once a gate is
  scheduled.
- **At and after a gate's height:** the gate is permanent. A node without it
  computes a different state root at the first affected transaction; the
  remedy is to install the correct binary and genesis on that node.

## 6. The three digests, and B2's handshake digest

- **Activation digest:** the chain id and every declared gate's name and
  height (set or not). **Protocol digest:** the activation digest and the
  compiled consensus limits. Peers compare the protocol digest at connect
  today. Neither reads the stored configuration record, so **the move changes
  neither**; this release moves both only because it declares two more gate
  names.
- **B2's handshake digest** (public PR #384, when it lands):
  `BLAKE3("sumchain/protocol-digest/v2" ‖ protocol digest ‖ running
  commitment)`, where the running commitment is `build(genesis)` in the schema
  the binary **writes**, never the recorded one.
  - Changing the binary's written-schema policy (3 → 4) changes the running
    commitment and therefore the handshake digest: a schema-4 writer and a
    schema-3 writer of the same genesis refuse each other. Same-window.
  - Migrating the stored record alone changes nothing in the declaration: the
    handshake preimage reads no record.
  - The same binary and genesis declare the same handshake digest whatever
    the recorded-schema history: a fresh schema-4 record, a schema-3 record
    moved, and a schema-3 record left as it stands all declare one value.
  - These three properties are tested in
    `crates/consensus/tests/consensus_config_schema4.rs`
    (`the_move_changes_the_recorded_commitment_but_not_what_b2_would_declare`),
    computing the digest exactly as B2's `handshake.rs` defines it.

Earlier steps: `consensus-config-schema-3.md` (that release wrote schema 3).
Tracker: #298.
