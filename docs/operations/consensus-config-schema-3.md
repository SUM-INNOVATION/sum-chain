# Consensus configuration schema 3: enablement, migration, gate scheduling

> **Status:** code enablement. No release, database migration, gate height or
> activation is part of the change that adds this document.

Schema 3 of the local consensus configuration
(`crates/consensus/src/consensus_config`) is schema 2 plus one optional field,
meaning "the behaviour that existed before" when absent:

| Id | Field | Effect from its height |
|---|---|---|
| `0x1043` | `node_registry_update_status_unsupported_enabled_from_height` | a transaction-borne node-registry `UpdateStatus` is refused |

This binary writes schema 3 (`PRODUCTION`: reads 1, 2 and 3, writes 3). That
freezes schema 3: its registry and encoding never change again, and a later
field goes into schema 4. The encoding is pinned by golden vectors in
`crates/consensus/tests/consensus_config.rs` (`schema_3_golden_vectors`); the
frozen schema-1 and schema-2 vectors are unchanged. The migration and refusal
rules below are tested in `crates/consensus/tests/consensus_config_schema3.rs`,
`crates/node/tests/acknowledge_consensus_config_guard.rs` and the node's boot
tests.

The record stays a local, unverified baseline. Nothing here is exchanged with
peers or authorizes anything on the network.

## 1. Installing the binary changes no rule

- **The gate is unset** in every tracked genesis, in `ChainParams::default()`
  and in the local-testnet generator. A node running this binary with it unset
  executes exactly what it executed before, `UpdateStatus` included.
  Installing the binary does **not** refuse `UpdateStatus`; only a scheduled
  height that the chain reaches does (section 4).
- **The upgrade is same-window.** Declaring the gate changes the activation and
  protocol digests whether or not it is set, and peers compare the protocol
  digest when they connect. A binary with this field and one without cannot
  run side by side: stop every validator, install, start them together.
- **Fresh data directory:** the node records schema 3 directly.
- **Data directory recorded in schema 1 or 2:** the node runs it exactly as it
  stands. It is compared in its own schema, never re-encoded at start, and the
  start reports `Unchanged`. At start the node logs that a schema transition is
  available, with both commitments.
- **`chain_getConsensusConfig` on such a node** reports the record's schema and
  commitment, and `matches_baseline: true`, because it compares in the record's
  schema as the start does. Its `running_commitment` is the schema-3 value, so
  it differs from `commitment` until the record moves.

## 2. Database migration (per node, stopped, one step)

The record moves to schema 3 in one step, from schema 1 or from schema 2. On a
stopped node:

```
sumchain acknowledge-consensus-config-schema --data-dir <dir> --show
sumchain acknowledge-consensus-config-schema --data-dir <dir> --old <recorded> --new <re-encoded>
```

- **`--show`** opens the database read-only, writes nothing, and prints the
  move this binary would make, with `--old` and `--new` exactly as the second
  command takes them. On a database already in schema 3 it says there is
  nothing to move.
- **The move** re-encodes the recorded rules, adding every field the newer
  schemas add as absent, and changes no rule. It keeps the old encoding in the
  append-only history, which every later start re-verifies. The record and its
  history entry are written in one durable batch: a crash before it commits
  leaves the old record, and the command can simply be run again.
- **The move refuses:**
  - anything but both exact commitments (the refusal of a wrong `--new` names
    the right one);
  - a database already in schema 3;
  - a database held by a running node.
- **After the move,** the next start with the same genesis reports `Unchanged`
  against the moved record.

The move is local and is not coordinated with other nodes. It is needed on
every node before the gate can be scheduled.

## 3. Scheduling the gate (after the move; a coordinated decision)

Scheduling the gate means writing two heights into the genesis of every node:
`peer_protocol_declaration_required_from_height` (P) and
`node_registry_update_status_unsupported_enabled_from_height` (H).

- **P at or below H.** Genesis validation refuses the gate without the
  peer-declaration deadline, or with it above the gate.
- **Move first.** Before the move, a genesis that sets H refuses start, naming
  the exact `acknowledge-consensus-config-schema --old … --new …` command, and
  the configuration record is not rewritten. The activation-height check runs
  earlier in the start and records the new future heights in the node's
  activation record; restoring the previous genesis is then an ordinary,
  permitted future reschedule.
- **After the move,** P and H at heights the chain has not reached are recorded
  at start as one gate reschedule of exactly those two fields (`0x1029` and
  `0x1043`). The next start reports `Unchanged`.
- **Not in the past.** A height at or below the node's current height cannot be
  scheduled. Once the chain reaches H, H can neither move nor be unset; no
  acknowledgement can permit it.
- **Identical everywhere, in one window.** Every validator must carry the same
  P and H. The heights are folded into the activation and protocol digests, so
  nodes with different values do not interoperate.

The order on each node is therefore: stop, take a copy of the data directory,
install, `--show`, move, write P and H into the genesis, start.

## 4. At and above H

An `UpdateStatus` transaction fails as any other failed node-registry operation
does:

- the receipt is `Failed(18)`;
- no node record and no active-archive snapshot changes;
- a fee of at least 1 is charged and advances the nonce. A zero fee, possible
  only where `min_fee` is 0, charges nothing and leaves the nonce unchanged.

Every other node-registry operation, and expired-challenge slashing, are
unchanged. Statuses set by `UpdateStatus` before H stay as they are.

## 5. Recovery limits

- **Before the move:** the record is unchanged, so a binary that reads its
  schema can still run the database, provided no gate height has been written.
- **After the move:** a binary that does not read schema 3 refuses the record
  ("written by a newer binary") and rewrites nothing. Returning to it needs the
  copy of the data directory taken before the move. Restoring that copy
  discards every block the node accepted after it was taken, so it is a
  recovery decision, not a routine rollback.
- **After P and H are written:** a binary without this field does not enforce
  the gate, and one that does not refuse unknown genesis fields would ignore it
  silently and diverge at the first `UpdateStatus` at or above H. Do not return
  such a binary to service once H is scheduled.
- **At and after H:** the gate is permanent. A node without it computes a
  different state root at the first `UpdateStatus` at or above H; the remedy is
  to install the correct binary and genesis on that node.

Earlier steps: `consensus-config-schema-2.md` (that release wrote schema 2).
Tracker: #298.
