# Consensus configuration schema 5: enablement, migration, abort points, forward recovery

> **Status:** code enablement (draft). No release, database migration, gate
> height or activation is part of the change that adds this document.

Schema 5 of the local consensus configuration
(`crates/consensus/src/consensus_config`) is schema 4 plus exactly three
optional fields, each meaning "the behaviour that existed before" when absent:

| Id | Field | Meaning |
|---|---|---|
| `0x1048` | `messaging_sponsored_envelope_verification_enabled_from_height` | from this height a sponsored `SendMessage` carries a version-2 sender envelope, verified in consensus |
| `0x1049` | `messaging_fee_nonce_accounting_enabled_from_height` | from this height every messaging operation is charged its fee and advances the sender's account nonce, once, succeeding or refused |
| `0x252b` | `sumchain_wire::messaging::SPONSORED_SEND_V2_TAG` | the compiled domain tag the version-2 envelope preimage begins with; committed exactly while `0x1048` is set |

**One value rule** is part of the schema, checked on every configuration built
or decoded in it: `0x252b` is present exactly when `0x1048` is, and is then the
compiled tag byte for byte. A record that breaks it was not produced by any
encoder and is refused as malformed.

This binary writes schema 5 (`PRODUCTION`: reads 1 to 5, writes 5). That
freezes schema 5: its registry and encoding never change again, and a later
field goes into schema 6. The encoding is unchanged (`CCFGv1`), and so is the
record layout. The encoding is pinned by golden vectors in
`crates/consensus/tests/consensus_config.rs` (`schema_5_golden_vectors`, and a
byte-for-byte comparison with the frozen schema-4 encoding); the frozen
schema-1 to schema-4 vectors are unchanged, and so are the canonical JSON,
genesis block hash, activation digest and protocol digest of every tracked
genesis file (`genesis_strict_fields_identity.rs`). The migration, the
pre-start revert and the refusals below are tested in
`crates/consensus/tests/consensus_config_schema5.rs`,
`crates/node/tests/acknowledge_consensus_config_guard.rs`,
`crates/node/tests/consensus_config_schema_crash.rs` (each write killed with
SIGKILL) and the node's boot tests.

The record stays a local, unverified baseline. Nothing here is exchanged with
peers or authorizes anything on the network.

## 1. Installing the binary changes no rule

- **The two gates are unset** in every tracked genesis and template, in
  `ChainParams::default()` and in the local-testnet generator, and the tag is
  absent while the envelope gate is unset. A node running this binary with
  them unset executes exactly what it executed before.
- **Against the schema-4 release, no gate name moves.** Schema 5 registers
  gates that the schema-4 release already declared (as draft fields it refused
  to activate), so the activation and protocol digests do not move.
- **This release declares the handshake digest** (section 6), in place of the
  protocol digest every earlier release declares. A handshake digest never
  equals a protocol digest, so this binary and any earlier release refuse
  each other at connect, whatever their rules: **the upgrade is same-window
  from every earlier release**, the schema-4 release included. Every
  validator and every follower moves in one window.
- **Against any release older than the schema-4 release** the two also differ
  in gate names (`consensus-config-schema-4.md`), so they would refuse each
  other by protocol digest as well.
- **Fresh data directory:** the node records schema 5 directly.
- **Data directory recorded in schema 1, 2, 3 or 4:** the node runs it exactly
  as it stands. It is compared in its own schema, never re-encoded at start,
  and the start reports `Unchanged`. Every start logs a WARN that a schema
  transition is available, with both commitments.
- **`chain_getConsensusConfig` on such a node** reports the record's schema and
  commitment, and `matches_baseline: true`. Its `running_commitment` is the
  schema-5 value, so it differs from `commitment` until the record moves.

## 2. The window

The move is one step from any older schema: a schema-3 record moves straight
to schema 5, adding schema 4's four gates and schema 5's three fields, absent.
There is no need to pass through schema 4.

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
  takes them. On a database already in schema 5 it says there is nothing to
  move. `--new` is a pure function of the record, so nodes that record the
  same commitment print the same `--new`.
- **The move** re-encodes the recorded rules, adding every field the newer
  schemas add as absent, and changes no rule. It consults no genesis. It keeps
  the old encoding in the append-only history, which every later start
  re-verifies. It writes exactly two rows, the record and one transition, in
  one durable batch: killed before the commit, the database is exactly the old
  one and the command can simply be run again; killed after it, the database
  is exactly the moved one.
- **The move refuses, and writes nothing,** on anything but both exact
  commitments (the refusal of a wrong `--new` names the right one), a database
  already in schema 5, a damaged record or history, a record of a schema this
  binary does not implement ("written by a newer binary"), and a database held
  by a running node.
- **After the move,** the next start with the same genesis reports `Unchanged`
  against the moved record. `chain_getConsensusConfig` then reports schema 5,
  `commitment` equal to `--new`, `running_commitment` equal to `commitment`,
  `matches_baseline: true`, and a history ending in `schema-transition`.
- **A record that disagrees with the genesis** refuses start before the move
  and after it, naming the same fields and `acknowledge-consensus-config`.

## 3. Abort points

As for schema 4 (`consensus-config-schema-4.md` §3), with "the running
release" being whichever release the node ran before the window (the schema-4
release, or an older one):

| Abort point | The database | Return to the running release |
|---|---|---|
| Before installing | unchanged | start the running release |
| After installing, before the move | unchanged: `check-finality-record` and `--show` are read-only, and the new binary has not started | reinstall the running release and start it |
| After the move, before any normal start attempt on any node | the moved record, which the running release refuses ("written by a newer binary") | the check before any revert of `consensus-config-schema-4.md` §3 on every node, validators and followers alike, then the pre-start revert on every node, then reinstall the running release and start it |
| After a normal start attempt of the new binary on any node | that node holds a start marker, written by that start, recording the moved record's transition count | no abort back for any node; forward recovery only (section 5) |

- **The revert** is `sumchain revert-consensus-config-schema` exactly as for
  schema 4: it writes back exactly the record the move replaced and removes the
  move's transition, in one durable batch, and is refused once a normal start
  was attempted on the moved record, once the chain has moved off the height
  the move was made at, or when the start marker disagrees with the history.
- **A marker the schema-4 release left does not block the revert.** A node
  that ran the schema-4 release holds a marker written at its schema-4
  record's transition count; that marker predates the move and is accounted
  for through the history.
- **A start attempt of the schema-4 release after the move closes the
  revert.** That release writes its start marker as its first write, before
  it reads the record; it then refuses the moved record ("written by a newer
  binary"), but its marker records the record as unreadable, and the revert
  refuses that as an uncertain migration state. Recovery from there is forward
  only, with this binary. So after the move, do not start the running release
  on that node; abort with the revert first. Releases older than the schema-4
  release write no marker (`consensus-config-schema-4.md` §3).
- **A database created by the schema-4 release and started exactly once** holds
  a marker written before its first baseline existed ("no configuration
  record"). The revert of a move made on it is refused as an uncertain
  migration state. Restart such a node once with its running release before
  the window: every start rewrites the marker, and the second one records the
  baseline. A database created before the marker existed, and started since
  by the schema-4 release, is not in this state.

## 4. Scheduling the gates (after the move; a coordinated decision)

Not part of this stage, and not authorized by it. For reference:

- **Move first.** Before the move, a genesis that sets the gates refuses start,
  naming the exact `acknowledge-consensus-config-schema --old … --new …`
  command, and the configuration record is not rewritten.
- **Both gates, one height.** Genesis validation refuses the two gates set
  apart, and refuses either without
  `peer_protocol_declaration_required_from_height` at or below it (both are
  remediation gates).
- **It is an acknowledgement, not a reschedule.** Setting the envelope gate
  also commits the envelope tag (`0x252b`), which is not a gate. A start with
  the gates scheduled therefore refuses and names
  `acknowledge-consensus-config --old … --new …`; the stopped-node
  acknowledgement records all three fields together, and the next start
  reports `Unchanged`. Unsetting them before their height moves the tag back
  and is acknowledged the same way.
- **Not in the past.** A height at or below the node's current height cannot
  be scheduled. Once the chain reaches the gates, they can neither move nor be
  unset.
- **Identical everywhere, in one window.** The heights enter the activation and
  protocol digests; nodes with different values do not interoperate.
- **Clients.** From the envelope gate, sponsored messages must be signed over
  the version-2 preimage; the relay accepts both forms below the gate.

## 5. After the first start attempt: forward recovery only

- **No rewind and no restore.** No step of recovery rewinds the chain or writes
  a data copy back over accepted blocks.
- **Recovery is a compatible binary:** stop the node, install it, start, and
  repeat the agreement checks. The start must report `Unchanged` with the same
  commitment.
- **Compatible** means all of:
  - it **writes schema 5**, and reads schema 5 and keeps reading schemas 1 to
    4;
  - its schema-5 registry is this one: the same three ids, names and types,
    encoding byte for byte as the schema-5 golden vectors;
  - it computes the same consensus-configuration commitment from the same
    genesis;
  - it declares the same activation-gate names;
  - it accepts the database's other formats (the application-journal format,
    the finality and certified-finality records, and the start marker).
- **Not compatible:** any release that reads only schemas up to 4, the
  schema-4 release included. It refuses the moved record ("written by a newer
  binary") and rewrites nothing in it. Do not start such a release on a moved
  node.
- **At and after a gate's height:** the gate is permanent.

## 6. The three digests, and B2's handshake digest

- **Activation digest and protocol digest:** unchanged by this release and by
  the move, on every tracked genesis (pinned in
  `genesis_strict_fields_identity.rs`).
- **The handshake digest** (rule R, `p2p-admission-and-compatibility.md` §2),
  which this release declares: `BLAKE3("sumchain/protocol-digest/v2" ‖
  protocol digest ‖ running commitment)`, where the running commitment is
  `build(genesis)` in the schema the binary writes, never the recorded one.
  - Changing the written schema from 4 to 5 changes the running commitment and
    therefore the handshake digest: a schema-5 writer and a schema-4 writer of
    the same genesis refuse each other even where both declare a handshake
    digest.
  - Migrating the stored record alone changes nothing in the declaration: a
    node whose record is still schema 3 and a node whose record moved declare
    the same value, and verify each other.
  - After the window, any change to an input of the running configuration (a
    gate height, or an acknowledged non-gate value such as `min_fee`) is
    same-window too: a node restarted on new inputs is refused by the others,
    and a node that refused it holds that refusal until it restarts itself.
  - Tested in `consensus_config_schema5.rs`
    (`the_move_changes_the_recorded_commitment_but_not_the_digests`),
    `handshake_digest.rs`, and the node's booted multi-node tests.

Earlier steps: `consensus-config-schema-4.md` (the release that wrote schema
4). Tracker: #298.
