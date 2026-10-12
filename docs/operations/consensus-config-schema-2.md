# Consensus configuration schema 2: enablement, release, migration, activation

> **Status:** code enablement only (#268). No release, database migration or
> gate activation is part of the change that adds this document.

Schema 2 of the local consensus configuration (`crates/consensus/src/consensus_config`)
is schema 1 plus ten optional fields, each meaning "the behaviour that existed
before" when absent:

| Id | Field | Issue |
|---|---|---|
| `0x103f` | `credential_schema_validation_enabled_from_height` | #277 |
| `0x1040` | `messaging_timestamp_units_enabled_from_height` | #278 |
| `0x1042` | `contract_error_rollback_enabled_from_height` | #279 |
| `0x0720` | `compute_pool_params` (the `CPPRMv1` encoding) | #215 |
| `0x1041` | `contract_metering_enabled_from_height` (refused at every configuration build until the metering values are ratified) | #279 |
| `0x0115` | `max_block_contract_gas`, only with `0x1041`, and at least `max_contract_gas` | #279 |
| `0x2716` | `METERED_ENGINE_IDENTITY`, committed exactly when `0x1041` is set; never while the values are unratified | #279 |
| `0x2717` | `METERED_COST_SCHEDULE`, committed exactly when `0x1041` is set; never while the values are unratified | #279 |
| `0x0116` | `max_contract_deploy_gas`, only with `0x1041`, at least `max_contract_gas` and at most `0x0115` | #279 |
| `0x252a` | `MESSAGING_TIMESTAMP_MS_PER_SECOND`, committed only while `0x1040` is set | #278 |

The metering fields' value rules (types, presence and byte shapes) are in
`schema::check_metering_relations` and are checked on every build and decode.

The record stays a local, unverified baseline. Nothing here is exchanged with
peers or authorizes anything on the network.

Four separate steps, each with its own decision:

## 1. Code enablement

The binary writes schema 2 (`PRODUCTION`: reads 1 and 2, writes 2). This freezes
schema 2: its registry and encoding never change again, and a later field goes
into schema 3. The encoding is pinned by golden vectors in
`crates/consensus/tests/consensus_config.rs` (`schema_2_golden_vectors`).

## 2. Release

A release built from that code behaves as follows.

- **Fresh data directory:** the node records schema 2 directly.
- **Data directory recorded in schema 1 by an earlier release:** the node runs it
  exactly as it stands. The record is compared in schema 1 and never
  re-encoded at start. At start the node logs that a schema transition is
  available, with both commitments.
- **Older binaries:** a binary that reads only schema 1 refuses to start on a
  schema-2 record ("written by a newer binary"). Rolling a node back after its
  record moved to schema 2 therefore needs that record's backup, or a binary
  that reads schema 2.

## 3. Database migration (per node, explicit)

On a stopped node, the operator moves its record to schema 2:

```
sumchain acknowledge-consensus-config-schema --data-dir <dir> --old <recorded> --new <re-encoded>
```

Both commitments are printed by the node at start. The command:
- re-encodes the recorded rules, adding the ten fields as absent, and changes
  no rule;
- keeps the old encoding in the append-only history, which every later start
  re-verifies;
- refuses anything but both exact commitments.

It is local and is not coordinated with other nodes.

## 4. Gate activation (separate, later decisions)

A schema-2 field can be set only after the node's record is in schema 2. Before
that, the node refuses to start, naming the command in step 3. Each activation
is then its own coordinated decision:

- **A future height for `0x103f` or `0x1042`:** recorded at start as an ordinary
  gate reschedule.
- **A height for `0x1040`:** also moves `0x252a`, which is not a gate. Start
  refuses and names `sumchain acknowledge-consensus-config`, which records both
  together.
- **Declaring `compute_pool_params`:** a parameter change, acknowledged the same
  way. The compute-pool gate itself is still refused by genesis validation.
- **`0x1041`:** refused until the metering values are ratified, by a later
  reviewed change. A metering height also commits `0x2716` and `0x2717`, so it is
  acknowledged as a change, not recorded as a reschedule. `0x0115` and `0x0116`
  are only valid together with it.

Tracker: #298 (F1–F4, F6).
