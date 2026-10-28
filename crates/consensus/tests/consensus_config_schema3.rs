//! ConsensusConfig schema 3 (#268): schema 2 plus the node-registry
//! `UpdateStatus` remediation gate (0x1043), which this binary writes.
//!
//! Every upgrade test starts from `tests/data/consensus_config_schema1_db.tsv`:
//! the exact `cf::META` entries the schema-1 release writes (a baseline, a
//! gate reschedule and an operator acknowledgement), loaded into a fresh
//! database byte for byte. A schema-2 database is that one moved by the
//! release that wrote schema 2 ([`SCHEMA_2_RELEASE`]).
//!
//! What an operator relies on, in order:
//!
//! * installing this binary changes nothing: a schema-1 or schema-2 record runs
//!   as it stands, compared in its own schema, never re-encoded at start;
//! * the gate cannot be set until the record is schema 3: before the move, a
//!   genesis that sets it refuses start and names the exact stopped-node
//!   command, both commitments included;
//! * the move is one step from schema 1 or schema 2, re-encodes the recorded
//!   rules, changes none, and keeps the older encoding in the history;
//! * after the move, setting the gate and its peer-declaration deadline at
//!   future heights is an ordinary future-gate reschedule; a height already
//!   reached, or a gate already passed, is refused;
//! * an older binary refuses a schema-3 record and rewrites nothing, so a
//!   moved node goes back to an older binary only from a copy of its
//!   database taken before the move.

use sumchain_consensus::consensus_config::{
    self as ccfg,
    record::{
        acknowledge_schema_transition_with, acknowledge_with, check_at_startup_with,
        pending_schema_transition_with, read_record_with, read_transitions_with, RECORD_KEY,
    },
    schema::{SCHEMA_2_ADDED, SCHEMA_3_ADDED},
    ConfigError, ConsensusConfig, SchemaPolicy, Source, StartupOutcome, TransitionKind, Value,
    PRODUCTION, SCHEMA_1, SCHEMA_2, SCHEMA_3,
};
use sumchain_crypto::KeyPair;
use sumchain_genesis::{ChainParams, Genesis, GenesisError};
use sumchain_primitives::Hash;
use sumchain_storage::{cf, Database};
use tempfile::TempDir;

/// The gate schema 3 adds.
const GATE: u16 = 0x1043;
const GATE_NAME: &str = "node_registry_update_status_unsupported_enabled_from_height";
/// `peer_protocol_declaration_required_from_height`, a schema-1 gate.
const PEER: u16 = 0x1029;

/// The release before schema 2: it read and wrote schema 1. (It knew schema 2
/// only as a draft; it is given schema 3 to know because a policy must name
/// every gate `ChainParams` declares to build at all, and with the gate unset
/// that adds nothing to the schema-1 record it writes.)
static PREVIOUS: SchemaPolicy = SchemaPolicy {
    reads: &[&SCHEMA_1],
    writes: &SCHEMA_1,
    knows: &SCHEMA_3,
};

/// The release that wrote schema 2: it read schemas 1 and 2, wrote 2, and knew
/// schema 3 only as a draft.
static SCHEMA_2_RELEASE: SchemaPolicy = SchemaPolicy {
    reads: &[&SCHEMA_1, &SCHEMA_2],
    writes: &SCHEMA_2,
    knows: &SCHEMA_3,
};

// ── the schema-1 fixture (as in `consensus_config_schema2.rs`) ──────────────

/// The commitment the schema-1 release recorded last for the fixture.
const C2: &str = "0x35d735e97b2c566a64adf1e64e993a91e279e84ee771dde6333d82fd53428d59";

fn h(s: &str) -> Hash {
    Hash::from_hex(s).unwrap()
}

fn g0() -> Genesis {
    let v = KeyPair::from_bytes([12u8; 32]);
    Genesis::new(
        1,
        1_734_624_000_000,
        vec![v.public_key().to_base58()],
        std::collections::HashMap::from([(v.address().to_base58(), 1_000_000u128)]),
        ChainParams::default(),
    )
}

/// The genesis the fixture's record describes.
fn g2() -> Genesis {
    let mut g = g0();
    g.params.nft_receipt_failure_enabled_from_height = Some(1_000);
    g.params.max_contract_gas += 1;
    g
}

/// [`g2`] scheduling the gate at `gate` and the peer-declaration deadline at
/// `peer`.
fn scheduled(peer: u64, gate: u64) -> Genesis {
    let mut g = g2();
    g.params.peer_protocol_declaration_required_from_height = Some(peer);
    g.params
        .node_registry_update_status_unsupported_enabled_from_height = Some(gate);
    g
}

/// Height of the fixture's last write.
const HEIGHT: u64 = 20;

fn fixture_entries() -> Vec<(Vec<u8>, Vec<u8>)> {
    let text = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/data/consensus_config_schema1_db.tsv"),
    )
    .unwrap();
    text.lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .map(|l| {
            let (k, v) = l.split_once('\t').expect("key\tvalue");
            (hex::decode(k).unwrap(), hex::decode(v).unwrap())
        })
        .collect()
}

/// A database holding exactly the schema-1 release's entries.
fn schema_1_database() -> (TempDir, Database) {
    let dir = TempDir::new().unwrap();
    let db = Database::open_default(dir.path()).unwrap();
    let mut batch = db.batch();
    for (k, v) in fixture_entries() {
        batch.put(cf::META, &k, &v).unwrap();
    }
    batch.commit_durable().unwrap();
    (dir, db)
}

/// The fixture moved to schema 2 by the release that wrote schema 2.
fn schema_2_database() -> (TempDir, Database) {
    let (dir, db) = schema_1_database();
    let p = pending_schema_transition_with(&db, &SCHEMA_2_RELEASE)
        .unwrap()
        .unwrap();
    acknowledge_schema_transition_with(&db, HEIGHT, p.old, p.new, &SCHEMA_2_RELEASE).unwrap();
    assert_eq!(
        read_record_with(&db, &SCHEMA_2_RELEASE)
            .unwrap()
            .unwrap()
            .config
            .schema()
            .number,
        2
    );
    (dir, db)
}

/// Every `consensus_config/` entry, in key order.
fn entries(db: &Database) -> Vec<(Vec<u8>, Vec<u8>)> {
    db.prefix_iter_checked(cf::META, b"consensus_config/")
        .unwrap()
        .map(|e| e.unwrap())
        .take_while(|(k, _)| k.starts_with(b"consensus_config/"))
        .map(|(k, v)| (k.to_vec(), v.to_vec()))
        .collect()
}

/// This binary's one-step move of `db` to schema 3, with the commitments it
/// offers.
fn move_to_schema_3(db: &Database) -> ccfg::SchemaTransitioned {
    let p = ccfg::pending_schema_transition(db).unwrap().unwrap();
    ccfg::acknowledge_schema_transition(db, HEIGHT, p.old, p.new).unwrap()
}

fn ids(changes: &[ccfg::FieldChange]) -> Vec<u16> {
    let mut v: Vec<u16> = changes.iter().map(|c| c.id).collect();
    v.sort();
    v
}

// ── schema 3 ────────────────────────────────────────────────────────────────

#[test]
fn schema_3_is_schema_2_plus_the_remediation_gate_and_this_binary_writes_it() {
    assert_eq!(SCHEMA_3.number, 3);
    assert!(std::ptr::eq(SCHEMA_3.previous.unwrap(), &SCHEMA_2));
    let added: Vec<(u16, &str)> = SCHEMA_3_ADDED
        .iter()
        .map(|a| (a.spec.id, a.spec.name))
        .collect();
    assert_eq!(added, [(GATE, GATE_NAME)]);
    let gate = &SCHEMA_3_ADDED[0];
    assert!(matches!(gate.source, Source::Gate));
    assert!(gate.spec.optional);
    assert_eq!(
        SCHEMA_3.specs().len(),
        SCHEMA_2.specs().len() + 1,
        "one field added"
    );
    assert_eq!(
        SCHEMA_3.added_since(&SCHEMA_1).len(),
        SCHEMA_2_ADDED.len() + 1
    );

    assert!(std::ptr::eq(PRODUCTION.writes, &SCHEMA_3));
    assert!(std::ptr::eq(PRODUCTION.knows, &SCHEMA_3));
    assert_eq!(
        PRODUCTION
            .reads
            .iter()
            .map(|s| s.number)
            .collect::<Vec<_>>(),
        [1, 2, 3],
        "older schemas are read for good"
    );
    for p in [&PRODUCTION, &PREVIOUS, &SCHEMA_2_RELEASE] {
        p.check().unwrap();
    }

    // Unset in every default: declaring the field schedules nothing.
    assert_eq!(
        ChainParams::default().node_registry_update_status_unsupported_enabled_from_height,
        None
    );
    assert_eq!(ccfg::build(&g2()).unwrap().get(GATE), Some(&Value::Absent));
}

#[test]
fn a_fresh_database_records_schema_3_directly() {
    let dir = TempDir::new().unwrap();
    let db = Database::open_default(dir.path()).unwrap();
    let expected = ccfg::build(&g2()).unwrap();
    assert_eq!(expected.schema().number, 3);
    assert_eq!(
        ccfg::check_at_startup(&db, &g2(), 0).unwrap(),
        StartupOutcome::Initialized {
            commitment: expected.commitment(),
            baseline_height: 0
        }
    );
    let r = ccfg::read_record(&db).unwrap().unwrap();
    assert_eq!(r.config, expected);
    assert_eq!(r.config.get(GATE), Some(&Value::Absent));
    assert_eq!(r.transition_count, 0);
    assert_eq!(ccfg::pending_schema_transition(&db).unwrap(), None);
    // And it is the schema-2 configuration plus the gate, absent.
    assert_eq!(
        ccfg::build_with(&g2(), &SCHEMA_2_RELEASE)
            .unwrap()
            .extend_to(&SCHEMA_3)
            .unwrap(),
        expected
    );
}

// ── installing the binary changes nothing ───────────────────────────────────

/// A schema-1 database runs as it stands, however often this binary starts,
/// and is offered the move straight to schema 3.
#[test]
fn a_schema_1_database_runs_as_it_stands_and_is_offered_schema_3_in_one_step() {
    let (_d, db) = schema_1_database();
    for _ in 0..3 {
        assert_eq!(
            ccfg::check_at_startup(&db, &g2(), HEIGHT).unwrap(),
            StartupOutcome::Unchanged { commitment: h(C2) }
        );
    }
    assert_eq!(entries(&db), fixture_entries(), "nothing written at start");
    let r = ccfg::read_record(&db).unwrap().unwrap();
    assert_eq!(r.config.schema().number, 1);
    let p = ccfg::pending_schema_transition(&db).unwrap().unwrap();
    assert_eq!((p.from_schema, p.to_schema), (1, 3));
    assert_eq!(p.old, h(C2));
    assert_eq!(p.new, r.config.extend_to(&SCHEMA_3).unwrap().commitment());
}

/// A schema-2 database runs as it stands, and is offered the move to schema 3.
#[test]
fn a_schema_2_database_runs_as_it_stands_and_is_offered_schema_3() {
    let (_d, db) = schema_2_database();
    let before = entries(&db);
    let r = ccfg::read_record(&db).unwrap().unwrap();
    for _ in 0..3 {
        assert_eq!(
            ccfg::check_at_startup(&db, &g2(), HEIGHT).unwrap(),
            StartupOutcome::Unchanged {
                commitment: r.commitment
            }
        );
    }
    assert_eq!(entries(&db), before, "nothing written at start");
    let p = ccfg::pending_schema_transition(&db).unwrap().unwrap();
    assert_eq!((p.from_schema, p.to_schema), (2, 3));
    assert_eq!(p.old, r.commitment);
}

// ── the move ────────────────────────────────────────────────────────────────

/// One step from schema 1: every field schemas 2 and 3 add is recorded absent,
/// the history keeps the schema-1 entries and gains one schema transition,
/// and the moved record runs unchanged.
#[test]
fn the_one_step_move_from_schema_1_keeps_the_rules_and_the_history() {
    let (_d, db) = schema_1_database();
    let old_history = ccfg::read_transitions(&db).unwrap();
    let done = move_to_schema_3(&db);
    assert_eq!((done.from_schema, done.to_schema), (1, 3));
    assert_eq!(done.from, h(C2));
    let mut expected_added: Vec<u16> = SCHEMA_2_ADDED
        .iter()
        .chain(SCHEMA_3_ADDED)
        .map(|a| a.spec.id)
        .collect();
    expected_added.sort();
    assert_eq!(done.added, expected_added);

    let r = ccfg::read_record(&db).unwrap().unwrap();
    assert_eq!(r.config.schema().number, 3);
    assert_eq!(r.commitment, done.to);
    for id in &expected_added {
        assert_eq!(r.config.get(*id), Some(&Value::Absent), "{id:#06x}");
    }
    let history = ccfg::read_transitions(&db).unwrap();
    assert_eq!(history.len(), old_history.len() + 1);
    assert_eq!(&history[..old_history.len()], &old_history[..]);
    assert_eq!(
        history.last().unwrap().kind,
        TransitionKind::SchemaTransition
    );

    assert_eq!(
        ccfg::check_at_startup(&db, &g2(), HEIGHT).unwrap(),
        StartupOutcome::Unchanged {
            commitment: done.to
        }
    );
    assert_eq!(ccfg::pending_schema_transition(&db).unwrap(), None);

    // Nothing left to move; a second run refuses and writes nothing.
    let before = entries(&db);
    let err = ccfg::acknowledge_schema_transition(&db, HEIGHT, done.to, done.to).unwrap_err();
    assert!(
        err.to_string().contains("already recorded in schema 3"),
        "{err}"
    );
    assert_eq!(entries(&db), before);
}

/// From schema 2 the move adds only 0x1043, and lands on exactly the
/// commitment the one-step move from schema 1 does: the same rules.
#[test]
fn the_move_from_schema_2_adds_only_the_gate_and_matches_the_one_step_move() {
    let (_d1, one) = schema_1_database();
    let via_one = move_to_schema_3(&one);

    let (_d2, two) = schema_2_database();
    let done = move_to_schema_3(&two);
    assert_eq!((done.from_schema, done.to_schema), (2, 3));
    assert_eq!(done.added, vec![GATE]);
    assert_eq!(done.to, via_one.to);
    assert_eq!(
        ccfg::check_at_startup(&two, &g2(), HEIGHT).unwrap(),
        StartupOutcome::Unchanged {
            commitment: done.to
        }
    );
}

/// The move names both commitments exactly; anything else refuses and writes
/// nothing.
#[test]
fn the_move_must_name_both_commitments_exactly() {
    let (_d, db) = schema_1_database();
    let p = ccfg::pending_schema_transition(&db).unwrap().unwrap();
    let zero = Hash::from_hex(&format!("0x{}", "00".repeat(32))).unwrap();
    let before = entries(&db);
    for (old, new) in [(zero, p.new), (p.old, zero), (p.new, p.old), (p.old, p.old)] {
        let err = ccfg::acknowledge_schema_transition(&db, HEIGHT, old, new).unwrap_err();
        assert!(matches!(err, ConfigError::Refused(_)), "{err}");
    }
    // The refusal of a wrong `--new` names the right one.
    let err = ccfg::acknowledge_schema_transition(&db, HEIGHT, p.old, zero).unwrap_err();
    assert!(err.to_string().contains(&p.new.to_string()), "{err}");
    assert_eq!(entries(&db), before);
}

// ── ordering: the gate waits for the move ───────────────────────────────────

/// Before the move, a genesis that schedules the gate — with its peer deadline
/// at or below it, as genesis validation requires — refuses start and names
/// the stopped-node command with both commitments; the field-level
/// acknowledgement refuses too. Nothing is written. Unset again, the node
/// starts unchanged.
#[test]
fn before_the_move_scheduling_the_gate_refuses_and_names_the_command() {
    for (label, (_d, db)) in [
        ("schema 1", schema_1_database()),
        ("schema 2", schema_2_database()),
    ] {
        let before = entries(&db);
        let r = ccfg::read_record(&db).unwrap().unwrap();
        let p = ccfg::pending_schema_transition(&db).unwrap().unwrap();
        let g = scheduled(HEIGHT + 100, HEIGHT + 200);
        g.validate().unwrap();

        let err = ccfg::check_at_startup(&db, &g, HEIGHT).unwrap_err();
        let text = err.to_string();
        assert!(matches!(err, ConfigError::Refused(_)), "{label}: {text}");
        assert!(text.contains(GATE_NAME), "{label}: {text}");
        assert!(
            text.contains(&format!(
                "acknowledge-consensus-config-schema --old {} --new {}",
                p.old, p.new
            )),
            "{label}: {text}"
        );

        let ack = ccfg::acknowledge(&db, &g, HEIGHT, r.commitment, r.commitment).unwrap_err();
        assert!(
            ack.to_string()
                .contains("acknowledge-consensus-config-schema"),
            "{label}: {ack}"
        );
        assert_eq!(entries(&db), before, "{label}: nothing written");

        assert_eq!(
            ccfg::check_at_startup(&db, &g2(), HEIGHT).unwrap(),
            StartupOutcome::Unchanged {
                commitment: r.commitment
            },
            "{label}"
        );
    }
}

/// After the move, scheduling the gate and its peer deadline at future
/// heights is an ordinary future-gate reschedule of exactly those two fields,
/// recorded in the history; the next start is unchanged.
#[test]
fn after_the_move_scheduling_the_gate_is_a_future_gate_reschedule() {
    let (_d, db) = schema_1_database();
    let moved = move_to_schema_3(&db);
    let g = scheduled(HEIGHT + 100, HEIGHT + 200);
    let out = ccfg::check_at_startup(&db, &g, HEIGHT).unwrap();
    let StartupOutcome::GatesRescheduled { from, to, changes } = out else {
        panic!("expected a reschedule, got {out:?}");
    };
    assert_eq!(from, moved.to);
    assert_eq!(to, ccfg::build(&g).unwrap().commitment());
    assert_eq!(ids(&changes), vec![PEER, GATE]);

    let history = ccfg::read_transitions(&db).unwrap();
    let last = history.last().unwrap();
    assert_eq!(last.kind, TransitionKind::GateReschedule);
    let mut changed = last.changed_ids.clone();
    changed.sort();
    assert_eq!(changed, vec![PEER, GATE]);

    let r = ccfg::read_record(&db).unwrap().unwrap();
    assert_eq!(r.config.get(GATE), Some(&Value::U64(HEIGHT + 200)));
    assert_eq!(r.config.get(PEER), Some(&Value::U64(HEIGHT + 100)));
    assert_eq!(
        ccfg::check_at_startup(&db, &g, HEIGHT + 1).unwrap(),
        StartupOutcome::Unchanged { commitment: to }
    );

    // Still ahead of the chain: it can be moved later, or unset again.
    let later = scheduled(HEIGHT + 100, HEIGHT + 300);
    assert!(matches!(
        ccfg::check_at_startup(&db, &later, HEIGHT + 2).unwrap(),
        StartupOutcome::GatesRescheduled { .. }
    ));
}

/// A height the chain has already reached cannot be scheduled, and once the
/// chain passes the gate it cannot move or be unset. Nothing is written.
#[test]
fn a_reached_height_or_a_passed_gate_is_refused() {
    // Scheduling at or below the current height.
    let (_d, db) = schema_1_database();
    move_to_schema_3(&db);
    let before = entries(&db);
    for at in [HEIGHT - 1, HEIGHT] {
        let err = ccfg::check_at_startup(&db, &scheduled(at, at), HEIGHT).unwrap_err();
        assert!(err.to_string().contains("already passed"), "{at}: {err}");
        assert!(err.to_string().contains(GATE_NAME), "{at}: {err}");
    }
    assert_eq!(entries(&db), before);

    // Scheduled, then passed.
    let g = scheduled(HEIGHT + 100, HEIGHT + 200);
    ccfg::check_at_startup(&db, &g, HEIGHT).unwrap();
    let passed = HEIGHT + 200;
    let before = entries(&db);
    for (label, moved) in [
        ("moved", scheduled(HEIGHT + 100, HEIGHT + 500)),
        ("unset", {
            let mut u = g2();
            u.params.peer_protocol_declaration_required_from_height = Some(HEIGHT + 100);
            u
        }),
    ] {
        let err = ccfg::check_at_startup(&db, &moved, passed).unwrap_err();
        assert!(err.to_string().contains("already passed"), "{label}: {err}");
        assert!(err.to_string().contains(GATE_NAME), "{label}: {err}");
        let r = ccfg::read_record(&db).unwrap().unwrap();
        let ack = ccfg::acknowledge(
            &db,
            &moved,
            passed,
            r.commitment,
            ccfg::build(&moved).unwrap().commitment(),
        )
        .unwrap_err();
        assert!(ack.to_string().contains("already passed"), "{label}: {ack}");
    }
    assert_eq!(entries(&db), before);
    assert!(matches!(
        ccfg::check_at_startup(&db, &g, passed).unwrap(),
        StartupOutcome::Unchanged { .. }
    ));
}

/// Genesis validation requires the peer-declaration deadline at or below the
/// gate, so the two are always scheduled together.
#[test]
fn the_gate_needs_the_peer_deadline_at_or_below_it() {
    let mut g = g2();
    g.params
        .node_registry_update_status_unsupported_enabled_from_height = Some(1_000);
    assert!(matches!(
        g.validate(),
        Err(GenesisError::RemediationGateWithoutPeerProtocolEnforcement { .. })
    ));
    g.params.peer_protocol_declaration_required_from_height = Some(1_001);
    assert!(matches!(
        g.validate(),
        Err(GenesisError::PeerProtocolEnforcementAfterRemediationGate { .. })
    ));
    for peer in [1_000, 999, 1] {
        g.params.peer_protocol_declaration_required_from_height = Some(peer);
        g.validate().unwrap();
    }
}

// ── older binaries ──────────────────────────────────────────────────────────

/// The release that recorded schema 1, and the one that wrote schema 2, both
/// refuse a schema-3 record — moved or fresh — and rewrite nothing. A moved
/// node returns to an older binary only from a copy of its database taken
/// before the move.
#[test]
fn older_binaries_refuse_a_schema_3_record_and_rewrite_nothing() {
    let (_d1, moved_from_1) = schema_1_database();
    move_to_schema_3(&moved_from_1);
    let (_d2, moved_from_2) = schema_2_database();
    move_to_schema_3(&moved_from_2);
    let fresh_dir = TempDir::new().unwrap();
    let fresh = Database::open_default(fresh_dir.path()).unwrap();
    ccfg::check_at_startup(&fresh, &g2(), 0).unwrap();

    for (label, db) in [
        ("moved from schema 1", &moved_from_1),
        ("moved from schema 2", &moved_from_2),
        ("fresh", &fresh),
    ] {
        let before = entries(db);
        let raw = db.get(cf::META, RECORD_KEY).unwrap().unwrap();
        for (who, policy) in [
            ("schema-1 release", &PREVIOUS),
            ("schema-2 release", &SCHEMA_2_RELEASE),
        ] {
            let err = read_record_with(db, policy).unwrap_err();
            assert!(
                matches!(err, ConfigError::RecordCorrupt(_)),
                "{label}, {who}: {err}"
            );
            assert!(
                err.to_string().contains("newer binary"),
                "{label}, {who}: {err}"
            );
            assert!(check_at_startup_with(db, &g2(), HEIGHT, policy).is_err());
            assert!(read_transitions_with(db, policy).is_err());
            let c = h(C2);
            assert!(acknowledge_with(db, &g2(), HEIGHT, c, c, policy).is_err());
            assert!(acknowledge_schema_transition_with(db, HEIGHT, c, c, policy).is_err());
            assert_eq!(
                ConsensusConfig::decode_with(&raw[87..], policy.reads),
                Err(ConfigError::UnknownSchema(3)),
                "{label}, {who}"
            );
            assert_eq!(&entries(db), &before, "{label}, {who}: nothing rewritten");
        }
        // This binary starts on it.
        assert!(matches!(
            ccfg::check_at_startup(db, &g2(), HEIGHT).unwrap(),
            StartupOutcome::Unchanged { .. }
        ));
    }
}
