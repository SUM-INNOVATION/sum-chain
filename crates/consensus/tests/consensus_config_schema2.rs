//! ConsensusConfig schema 2 (#268): the append-only successor of the frozen
//! schema 1, and the explicit, acknowledged move of a stored schema-1 record
//! into it.
//!
//! Every upgrade test starts from `tests/data/consensus_config_schema1_db.tsv`:
//! the exact `cf::META` entries the schema-1 release writes (a baseline, a
//! gate reschedule and an operator acknowledgement), loaded into a fresh
//! database byte for byte.
//!
//! Schema 2 is a draft in production (its fields held absent, never read or
//! written). The tests enable it through test-only policies: the real
//! [`SCHEMA_2`], and [`TEST_SCHEMA_2`], which adds one test-only example
//! field. Nothing here registers a production field.

use std::cell::Cell;

use sumchain_consensus::consensus_config::{
    self as ccfg,
    codec::commitment_of,
    fields::{FieldSpec, ListOrder, Ty},
    record::{
        acknowledge_schema_transition_with, acknowledge_with, check_at_startup_with,
        pending_schema_transition_with, read_record_with, read_transitions_with, RECORD_KEY,
        TRANSITION_PREFIX,
    },
    schema::SCHEMA_2_ADDED,
    AddedField, ConfigError, ConsensusConfig, Schema, SchemaPolicy, Source, StartupOutcome,
    TransitionKind, Value, PRODUCTION, SCHEMA_1, SCHEMA_2,
};
use sumchain_crypto::KeyPair;
use sumchain_genesis::{ChainParams, Genesis};
use sumchain_primitives::Hash;
use sumchain_storage::{cf, Database};
use tempfile::TempDir;

// ── test-only schema 2 ──────────────────────────────────────────────────────

thread_local! {
    /// The value the test-only example field computes, per test thread.
    static EXAMPLE: Cell<Option<u64>> = const { Cell::new(None) };
}

fn example_value(_: &Genesis) -> Value {
    EXAMPLE.with(|c| c.get()).map_or(Value::Absent, Value::U64)
}

fn set_example(v: Option<u64>) {
    EXAMPLE.with(|c| c.set(v));
}

/// An id no production schema uses: test only.
const EXAMPLE_ID: u16 = 0x7f00;

const fn example_spec(id: u16, name: &'static str, optional: bool) -> FieldSpec {
    FieldSpec {
        id,
        name,
        ty: Ty::U64,
        optional,
        item_width: None,
        list_order: ListOrder::SortedUnique,
    }
}

/// What a #277/#278-style change appends to `SCHEMA_2_ADDED`, here a
/// test-only parameter so that it can be moved freely.
const EXAMPLE_FIELD: AddedField = AddedField {
    spec: example_spec(EXAMPLE_ID, "test_only_example_parameter", true),
    source: Source::Param(example_value),
};

/// The real schema 2's registered fields followed by [`EXAMPLE_FIELD`]: every gate
/// `ChainParams` declares keeps its id, so the test schema builds.
const TEST_ADDED_ARRAY: [AddedField; SCHEMA_2_ADDED.len() + 1] = {
    let mut out = [EXAMPLE_FIELD; SCHEMA_2_ADDED.len() + 1];
    let mut i = 0;
    while i < SCHEMA_2_ADDED.len() {
        out[i] = SCHEMA_2_ADDED[i];
        i += 1;
    }
    out
};
const TEST_ADDED: &[AddedField] = &TEST_ADDED_ARRAY;

/// Ids the real schema 2 adds, ascending.
fn real_added_ids() -> Vec<u16> {
    let mut ids: Vec<u16> = SCHEMA_2_ADDED.iter().map(|a| a.spec.id).collect();
    ids.sort();
    ids
}

/// Ids the test schema 2 adds, ascending.
fn test_added_ids() -> Vec<u16> {
    let mut ids = real_added_ids();
    ids.push(EXAMPLE_ID);
    ids.sort();
    ids
}

static TEST_SCHEMA_2: Schema = Schema {
    number: 2,
    previous: Some(&SCHEMA_1),
    added: TEST_ADDED,
};

/// A binary that reads schemas 1 and 2 and writes 2.
static ENABLED: SchemaPolicy = SchemaPolicy {
    reads: &[&SCHEMA_1, &TEST_SCHEMA_2],
    writes: &TEST_SCHEMA_2,
    knows: &TEST_SCHEMA_2,
};

/// The production shape — reads and writes schema 1, schema 2 a draft — with
/// the example field registered in the draft.
static DRAFT: SchemaPolicy = SchemaPolicy {
    reads: &[&SCHEMA_1],
    writes: &SCHEMA_1,
    knows: &TEST_SCHEMA_2,
};

/// The real schema 2 enabled, as the change that freezes it would.
static REAL_ENABLED: SchemaPolicy = SchemaPolicy {
    reads: &[&SCHEMA_1, &SCHEMA_2],
    writes: &SCHEMA_2,
    knows: &SCHEMA_2,
};

// ── the schema-1 fixture ────────────────────────────────────────────────────

/// Commitments the schema-1 release computed for g0, g1, g2.
const C0: &str = "0x1e861d23f2ad2d49dc2de0fb827ca35f8cdc42c39a3245aa76272a7564ef2e62";
const C1: &str = "0xb9ec368e6f5ae51ebce84e1fdc0cd45b0aa447a5d6be478653990a6b538efb8f";
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
fn g1() -> Genesis {
    let mut g = g0();
    g.params.nft_receipt_failure_enabled_from_height = Some(1_000);
    g
}
fn g2() -> Genesis {
    let mut g = g1();
    g.params.max_contract_gas += 1;
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

/// A database holding exactly the fixture's entries.
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

/// Every `consensus_config/` entry, in key order.
fn entries(db: &Database) -> Vec<(Vec<u8>, Vec<u8>)> {
    db.prefix_iter_checked(cf::META, b"consensus_config/")
        .unwrap()
        .map(|e| e.unwrap())
        .take_while(|(k, _)| k.starts_with(b"consensus_config/"))
        .map(|(k, v)| (k.to_vec(), v.to_vec()))
        .collect()
}

fn transition_key(seq: u64) -> Vec<u8> {
    let mut k = TRANSITION_PREFIX.to_vec();
    k.extend_from_slice(&seq.to_be_bytes());
    k
}

/// The commitment the fixture's record moves to under `policy`.
fn moved_commitment(db: &Database, policy: &SchemaPolicy) -> Hash {
    pending_schema_transition_with(db, policy)
        .unwrap()
        .expect("a transition is available")
        .new
}

/// The fixture moved to schema 2 under `ENABLED`.
fn transitioned() -> (TempDir, Database, Hash) {
    let (dir, db) = schema_1_database();
    let new = moved_commitment(&db, &ENABLED);
    acknowledge_schema_transition_with(&db, HEIGHT, h(C2), new, &ENABLED).unwrap();
    (dir, db, new)
}

// ── schema 1 stays as released ──────────────────────────────────────────────

/// The fixture is what this binary's schema-1 path writes today, byte for
/// byte: the production path is unchanged.
#[test]
fn the_fixture_is_what_the_schema_1_path_still_writes() {
    let dir = TempDir::new().unwrap();
    let db = Database::open_default(dir.path()).unwrap();
    ccfg::check_at_startup(&db, &g0(), 0).unwrap();
    ccfg::check_at_startup(&db, &g1(), 10).unwrap();
    ccfg::acknowledge(&db, &g2(), HEIGHT, h(C1), h(C2)).unwrap();
    assert_eq!(entries(&db), fixture_entries());

    let (_d, fx) = schema_1_database();
    let r = ccfg::read_record(&fx).unwrap().unwrap();
    assert_eq!(r.config.schema().number, 1);
    assert_eq!(r.initial_commitment, h(C0));
    assert_eq!(r.commitment, h(C2));
    let kinds: Vec<_> = ccfg::read_transitions(&fx)
        .unwrap()
        .iter()
        .map(|t| t.kind)
        .collect();
    assert_eq!(
        kinds,
        [
            TransitionKind::GateReschedule,
            TransitionKind::OperatorAcknowledged
        ]
    );
}

#[test]
fn this_binary_keeps_a_schema_1_database_as_it_is() {
    let (_d, db) = schema_1_database();
    assert_eq!(
        ccfg::check_at_startup(&db, &g2(), HEIGHT).unwrap(),
        StartupOutcome::Unchanged { commitment: h(C2) }
    );
    assert_eq!(ccfg::pending_schema_transition(&db).unwrap(), None);
    let err = ccfg::acknowledge_schema_transition(&db, HEIGHT, h(C2), h(C2)).unwrap_err();
    assert!(
        err.to_string().contains("already recorded in schema 1"),
        "{err}"
    );
    assert_eq!(entries(&db), fixture_entries());
}

#[test]
fn the_production_schema_2_is_a_well_formed_draft_of_dormant_gates() {
    // Every field registered so far is a gate, dormant in every default genesis.
    let defaults = ChainParams::default().activation_heights();
    for added in SCHEMA_2_ADDED {
        assert!(matches!(added.source, Source::Gate), "{}", added.spec.name);
        assert_eq!(
            defaults
                .iter()
                .find(|(n, _)| *n == added.spec.name)
                .map(|(_, h)| *h),
            Some(None),
            "{} is a dormant ChainParams gate",
            added.spec.name
        );
    }
    assert!(
        SCHEMA_2_ADDED.iter().any(|a| a.spec.id == 0x103f
            && a.spec.name == "credential_schema_validation_enabled_from_height"),
        "#277 holds 0x103f"
    );
    assert!(
        SCHEMA_2_ADDED.iter().any(|a| a.spec.id == 0x1040
            && a.spec.name == "messaging_timestamp_units_enabled_from_height"),
        "#278 holds 0x1040"
    );
    assert_eq!(SCHEMA_2.number, 2);
    assert_eq!(PRODUCTION.writes.number, 1);
    assert_eq!(
        PRODUCTION
            .reads
            .iter()
            .map(|s| s.number)
            .collect::<Vec<_>>(),
        [1]
    );
    assert!(std::ptr::eq(PRODUCTION.knows, &SCHEMA_2));
    PRODUCTION.check().unwrap();
    REAL_ENABLED.check().unwrap();
    ENABLED.check().unwrap();
    DRAFT.check().unwrap();
}

// ── a draft field is registered, never activated ────────────────────────────

/// Dormant, a field added after schema 1 leaves the schema-1 configuration —
/// and so every rule it describes — exactly as before; set, it refuses.
#[test]
fn a_draft_field_is_held_dormant_and_refused_when_set() {
    set_example(None);
    assert_eq!(
        ccfg::build_with(&g2(), &DRAFT).unwrap(),
        ccfg::build(&g2()).unwrap()
    );
    assert_eq!(ccfg::build_with(&g2(), &DRAFT).unwrap().commitment(), h(C2));

    set_example(Some(5));
    let err = ccfg::build_with(&g2(), &DRAFT).unwrap_err();
    assert!(
        err.to_string().contains("test_only_example_parameter"),
        "{err}"
    );

    let (_d, db) = schema_1_database();
    let err = check_at_startup_with(&db, &g2(), HEIGHT, &DRAFT).unwrap_err();
    assert!(matches!(err, ConfigError::Refused(_)), "{err}");
    assert!(err.to_string().contains("not activate"), "{err}");
    assert_eq!(entries(&db), fixture_entries());
    set_example(None);
}

// ── upgrade from a schema-1 database ────────────────────────────────────────

#[test]
fn a_schema_2_binary_runs_a_schema_1_database_unchanged_until_acknowledged() {
    set_example(None);
    let (_d, db) = schema_1_database();
    // Starts, compares in schema 1, re-encodes nothing — however often.
    for _ in 0..2 {
        assert_eq!(
            check_at_startup_with(&db, &g2(), HEIGHT, &ENABLED).unwrap(),
            StartupOutcome::Unchanged { commitment: h(C2) }
        );
        assert_eq!(entries(&db), fixture_entries());
    }
    let pending = pending_schema_transition_with(&db, &ENABLED)
        .unwrap()
        .unwrap();
    assert_eq!((pending.from_schema, pending.to_schema), (1, 2));
    assert_eq!(pending.old, h(C2));
    let recorded = read_record_with(&db, &ENABLED).unwrap().unwrap();
    assert_eq!(
        pending.new,
        recorded
            .config
            .extend_to(&TEST_SCHEMA_2)
            .unwrap()
            .commitment()
    );
    assert_ne!(pending.new, h(C2), "the schema is part of the commitment");
}

#[test]
fn the_schema_transition_must_name_both_commitments_exactly() {
    let (_d, db) = schema_1_database();
    let new = moved_commitment(&db, &ENABLED);
    let zero = Hash::from([0u8; 32]);
    for (old, n) in [(zero, new), (h(C2), zero), (h(C2), h(C2)), (new, new)] {
        let err = acknowledge_schema_transition_with(&db, HEIGHT, old, n, &ENABLED).unwrap_err();
        assert!(matches!(err, ConfigError::Refused(_)), "{err}");
    }
    assert_eq!(entries(&db), fixture_entries());
}

#[test]
fn the_schema_transition_moves_the_record_and_keeps_its_history() {
    set_example(None);
    let (_d, db) = schema_1_database();
    let fixture = fixture_entries();
    let new = moved_commitment(&db, &ENABLED);

    let done = acknowledge_schema_transition_with(&db, HEIGHT, h(C2), new, &ENABLED).unwrap();
    assert_eq!(done.seq, 3);
    assert_eq!((done.from_schema, done.to_schema), (1, 2));
    assert_eq!((done.from, done.to), (h(C2), new));
    assert_eq!(done.added, test_added_ids());

    let r = read_record_with(&db, &ENABLED).unwrap().unwrap();
    assert_eq!(r.config.schema().number, 2);
    assert_eq!(r.commitment, new);
    assert_eq!(r.initial_commitment, h(C0), "history start preserved");
    assert_eq!(r.baseline_height, 0);
    assert_eq!(r.transition_count, 3);
    assert_eq!(r.config.get(EXAMPLE_ID), Some(&Value::Absent));

    // The schema-1 history is untouched, byte for byte.
    let after = entries(&db);
    assert_eq!(after[1], fixture[1]);
    assert_eq!(after[2], fixture[2]);
    // The new entry keeps the schema-1 encoding it replaced.
    let history = read_transitions_with(&db, &ENABLED).unwrap();
    let t = &history[2];
    assert_eq!(t.kind, TransitionKind::SchemaTransition);
    assert_eq!(t.kind.label(), "schema-transition");
    assert_eq!(t.at_height, HEIGHT);
    assert_eq!(t.changed_ids, test_added_ids());
    let old = ConsensusConfig::decode(&t.old_encoding).expect("a schema-1 encoding");
    assert_eq!(old.schema().number, 1);
    assert_eq!(commitment_of(&t.old_encoding), h(C2));
    let fixture_record = ccfg::read_record(&{
        let (_d2, fx) = schema_1_database();
        fx
    })
    .unwrap()
    .unwrap();
    assert_eq!(old, fixture_record.config);

    // Restart: the moved record matches, nothing is pending, a second
    // transition has nothing to do.
    for _ in 0..2 {
        assert_eq!(
            check_at_startup_with(&db, &g2(), HEIGHT, &ENABLED).unwrap(),
            StartupOutcome::Unchanged { commitment: new }
        );
    }
    assert_eq!(pending_schema_transition_with(&db, &ENABLED).unwrap(), None);
    let err = acknowledge_schema_transition_with(&db, HEIGHT, new, new, &ENABLED).unwrap_err();
    assert!(err.to_string().contains("already recorded"), "{err}");
    assert_eq!(read_transitions_with(&db, &ENABLED).unwrap().len(), 3);
}

/// After the move, a schema-2 field is a field like any other: setting it is
/// refused at start and accepted only by the existing acknowledgement.
#[test]
fn after_the_transition_schema_2_fields_follow_the_existing_rules() {
    let (_d, db, new) = transitioned();
    set_example(Some(7));
    let err = check_at_startup_with(&db, &g2(), HEIGHT, &ENABLED).unwrap_err();
    assert!(
        err.to_string().contains("test_only_example_parameter"),
        "{err}"
    );
    assert!(
        err.to_string().contains("acknowledge-consensus-config"),
        "{err}"
    );
    let now = ccfg::build_with(&g2(), &ENABLED).unwrap().commitment();
    let done = acknowledge_with(&db, &g2(), HEIGHT, new, now, &ENABLED).unwrap();
    assert_eq!(done.seq, 4);
    assert_eq!(done.changes[0].id, EXAMPLE_ID);
    assert_eq!(
        check_at_startup_with(&db, &g2(), HEIGHT, &ENABLED).unwrap(),
        StartupOutcome::Unchanged { commitment: now }
    );
    set_example(None);
}

/// Before the move, a value only schema 2 can express refuses — at start and
/// in the field-level acknowledgement — and names the schema transition. The
/// two are never combined.
#[test]
fn before_the_transition_a_schema_2_value_refuses_and_names_the_transition() {
    let (_d, db) = schema_1_database();
    let new = moved_commitment(&db, &ENABLED);
    set_example(Some(5));
    let err = check_at_startup_with(&db, &g2(), HEIGHT, &ENABLED).unwrap_err();
    let msg = err.to_string();
    assert!(matches!(err, ConfigError::Refused(_)), "{msg}");
    assert!(msg.contains("acknowledge-consensus-config-schema"), "{msg}");
    assert!(msg.contains(C2), "{msg}");
    assert!(msg.contains(&new.to_string()), "{msg}");
    let err = acknowledge_with(&db, &g2(), HEIGHT, h(C2), new, &ENABLED).unwrap_err();
    assert!(err.to_string().contains("schema 1 cannot express"), "{err}");
    assert_eq!(entries(&db), fixture_entries());
    set_example(None);
}

#[test]
fn a_fresh_database_records_schema_2_directly() {
    set_example(None);
    let dir = TempDir::new().unwrap();
    let db = Database::open_default(dir.path()).unwrap();
    let out = check_at_startup_with(&db, &g2(), 0, &ENABLED).unwrap();
    let expected = ccfg::build_with(&g2(), &ENABLED).unwrap();
    assert_eq!(expected.schema().number, 2);
    assert_eq!(
        out,
        StartupOutcome::Initialized {
            commitment: expected.commitment(),
            baseline_height: 0
        }
    );
    let r = read_record_with(&db, &ENABLED).unwrap().unwrap();
    assert_eq!(r.config, expected);
    assert_eq!(r.transition_count, 0);
    assert_eq!(pending_schema_transition_with(&db, &ENABLED).unwrap(), None);
}

/// The real schema 2: the transition re-encodes, adding only its registered
/// fields, all absent.
#[test]
fn the_real_schema_2_transition_adds_only_its_registered_fields_absent() {
    let (_d, db) = schema_1_database();
    let new = moved_commitment(&db, &REAL_ENABLED);
    let done = acknowledge_schema_transition_with(&db, HEIGHT, h(C2), new, &REAL_ENABLED).unwrap();
    assert_eq!(done.added, real_added_ids());
    let r = read_record_with(&db, &REAL_ENABLED).unwrap().unwrap();
    for id in real_added_ids() {
        assert_eq!(r.config.get(id), Some(&Value::Absent), "{id:#06x}");
    }
    assert_eq!(
        check_at_startup_with(&db, &g2(), HEIGHT, &REAL_ENABLED).unwrap(),
        StartupOutcome::Unchanged { commitment: new }
    );
    // A schema-1 binary refuses it too.
    assert!(matches!(
        ccfg::read_record(&db),
        Err(ConfigError::RecordCorrupt(_))
    ));
}

// ── older binaries ──────────────────────────────────────────────────────────

/// A binary that reads only schema 1 — this one in production, and the
/// released schema-1 binary through the same decode path — refuses a schema-2
/// record and rewrites nothing.
#[test]
fn a_schema_1_binary_refuses_a_schema_2_record() {
    let (_d, db, _new) = transitioned();
    let before = entries(&db);

    let err = ccfg::read_record(&db).unwrap_err();
    assert!(matches!(err, ConfigError::RecordCorrupt(_)), "{err}");
    assert!(err.to_string().contains("schema 2"), "{err}");
    assert!(err.to_string().contains("newer binary"), "{err}");

    let err = ccfg::check_at_startup(&db, &g2(), HEIGHT).unwrap_err();
    assert!(err.to_string().contains("newer binary"), "{err}");
    assert!(ccfg::acknowledge(&db, &g2(), HEIGHT, h(C2), h(C2)).is_err());
    assert!(ccfg::acknowledge_schema_transition(&db, HEIGHT, h(C2), h(C2)).is_err());

    let raw = db.get(cf::META, RECORD_KEY).unwrap().unwrap();
    assert_eq!(
        ConsensusConfig::decode(&raw[87..]),
        Err(ConfigError::UnknownSchema(2))
    );
    assert_eq!(entries(&db), before, "nothing rewritten");
}

// ── interrupted transition ──────────────────────────────────────────────────

/// The record and its transition are one durable batch. A crash before the
/// batch commits leaves the schema-1 database, from which the transition can
/// simply be run again.
#[test]
fn a_crash_before_the_batch_commits_leaves_schema_1_and_can_be_retried() {
    let (dir, db) = schema_1_database();
    let new = moved_commitment(&db, &ENABLED);
    // Stage the transition's batch and lose it, as a crash would.
    {
        let mut batch = db.batch();
        batch.put(cf::META, &transition_key(3), b"staged").unwrap();
        drop(batch);
    }
    drop(db);
    let db = Database::open_default(dir.path()).unwrap();
    assert_eq!(entries(&db), fixture_entries());
    assert_eq!(
        check_at_startup_with(&db, &g2(), HEIGHT, &ENABLED).unwrap(),
        StartupOutcome::Unchanged { commitment: h(C2) }
    );
    acknowledge_schema_transition_with(&db, HEIGHT, h(C2), new, &ENABLED).unwrap();
    assert_eq!(
        read_record_with(&db, &ENABLED)
            .unwrap()
            .unwrap()
            .config
            .schema()
            .number,
        2
    );
}

/// A crash after the batch commits leaves schema 2, complete, across a
/// reopen; running the transition again changes nothing.
#[test]
fn a_crash_after_the_batch_commits_leaves_schema_2_complete() {
    let (dir, db, new) = transitioned();
    let after = entries(&db);
    drop(db);
    let db = Database::open_default(dir.path()).unwrap();
    assert_eq!(entries(&db), after);
    assert_eq!(
        check_at_startup_with(&db, &g2(), HEIGHT, &ENABLED).unwrap(),
        StartupOutcome::Unchanged { commitment: new }
    );
    assert!(acknowledge_schema_transition_with(&db, HEIGHT, h(C2), new, &ENABLED).is_err());
    assert_eq!(entries(&db), after);
}

/// A database holding only half of the transition — which one batch rules
/// out, and only damage can produce — is refused, never repaired or recreated.
#[test]
fn half_a_transition_is_refused_and_never_repaired() {
    let (_d, moved, _new) = transitioned();
    let moved_entries = entries(&moved);
    let new_record = moved_entries[0].clone();
    let new_transition = moved_entries[3].clone();

    // Transition entry written, record not.
    let (_d1, db) = schema_1_database();
    db.put(cf::META, &new_transition.0, &new_transition.1)
        .unwrap();
    let before = entries(&db);
    for policy in [&ENABLED, &PRODUCTION] {
        let err = check_at_startup_with(&db, &g2(), HEIGHT, policy).unwrap_err();
        assert!(matches!(err, ConfigError::RecordCorrupt(_)), "{err}");
    }
    assert!(acknowledge_schema_transition_with(&db, HEIGHT, h(C2), h(C2), &ENABLED).is_err());
    assert_eq!(entries(&db), before);

    // Record written, transition entry not.
    let (_d2, db) = schema_1_database();
    db.put(cf::META, &new_record.0, &new_record.1).unwrap();
    let before = entries(&db);
    let err = check_at_startup_with(&db, &g2(), HEIGHT, &ENABLED).unwrap_err();
    assert!(matches!(err, ConfigError::RecordCorrupt(_)), "{err}");
    assert_eq!(entries(&db), before);
}

// ── corruption ──────────────────────────────────────────────────────────────

fn tamper(db: &Database, key: &[u8], f: impl FnOnce(&mut Vec<u8>)) {
    let mut raw = db.get(cf::META, key).unwrap().unwrap();
    f(&mut raw);
    db.put(cf::META, key, &raw).unwrap();
}

/// Offsets inside a transition entry.
const T_KIND: usize = 2 + 8;
const T_CHANGED_IDS: usize = 2 + 8 + 1 + 8 + 32 + 32 + 2;

type Damage = Box<dyn Fn(&Database)>;

#[test]
fn a_damaged_schema_2_database_is_refused_and_never_recreated() {
    let cases: Vec<(&str, Damage)> = vec![
        (
            "schema transition's old encoding flipped",
            Box::new(|db| tamper(db, &transition_key(3), |r| *r.last_mut().unwrap() ^= 1)),
        ),
        (
            "schema transition lists another field",
            Box::new(|db| tamper(db, &transition_key(3), |r| r[T_CHANGED_IDS] ^= 1)),
        ),
        (
            "an acknowledgement relabelled a schema transition",
            Box::new(|db| tamper(db, &transition_key(2), |r| r[T_KIND] = 3)),
        ),
        (
            "schema transition relabelled an acknowledgement and a gate",
            Box::new(|db| tamper(db, &transition_key(3), |r| r[T_KIND] = 9)),
        ),
        (
            "record schema unknown to every binary",
            Box::new(|db| tamper(db, RECORD_KEY, |r| r[87 + 7] = 3)),
        ),
        (
            "record encoding flipped",
            Box::new(|db| tamper(db, RECORD_KEY, |r| *r.last_mut().unwrap() ^= 1)),
        ),
        (
            "schema-1 history entry removed",
            Box::new(|db| db.delete(cf::META, &transition_key(1)).unwrap()),
        ),
    ];
    for (what, damage) in cases {
        let (_d, db, _new) = transitioned();
        damage(&db);
        let before = entries(&db);
        let err = check_at_startup_with(&db, &g2(), HEIGHT, &ENABLED).unwrap_err();
        assert!(
            matches!(err, ConfigError::RecordCorrupt(_)),
            "{what}: {err}"
        );
        assert!(
            acknowledge_schema_transition_with(&db, HEIGHT, h(C2), h(C2), &ENABLED).is_err(),
            "{what}"
        );
        assert_eq!(entries(&db), before, "{what}: rewritten");
    }
}

/// A schema-1 database carrying a forged schema transition is refused: there
/// is no schema it re-encodes into.
#[test]
fn a_schema_transition_in_a_schema_1_history_is_refused() {
    let (_d, db) = schema_1_database();
    tamper(&db, &transition_key(2), |r| r[T_KIND] = 3);
    for policy in [&PRODUCTION, &ENABLED] {
        let err = check_at_startup_with(&db, &g2(), HEIGHT, policy).unwrap_err();
        assert!(matches!(err, ConfigError::RecordCorrupt(_)), "{err}");
    }
}

// ── the registry rules ──────────────────────────────────────────────────────

const REUSES_A_SCHEMA_1_ID: &[AddedField] = &[AddedField {
    spec: example_spec(0x0001, "chain_id_again", true),
    source: Source::Param(example_value),
}];
const REUSES_A_SCHEMA_1_NAME: &[AddedField] = &[AddedField {
    spec: example_spec(EXAMPLE_ID, "chain_id", true),
    source: Source::Param(example_value),
}];
const REQUIRED: &[AddedField] = &[AddedField {
    spec: example_spec(EXAMPLE_ID, "required_example", false),
    source: Source::Param(example_value),
}];
const GATE_OUTSIDE_RANGE: &[AddedField] = &[AddedField {
    spec: example_spec(EXAMPLE_ID, "example_enabled_from_height", true),
    source: Source::Gate,
}];
const PARAM_IN_GATE_RANGE: &[AddedField] = &[AddedField {
    spec: example_spec(0x1ffe, "example_param", true),
    source: Source::Param(example_value),
}];
static BAD_1: Schema = Schema {
    number: 2,
    previous: Some(&SCHEMA_1),
    added: REUSES_A_SCHEMA_1_ID,
};
static BAD_2: Schema = Schema {
    number: 2,
    previous: Some(&SCHEMA_1),
    added: REUSES_A_SCHEMA_1_NAME,
};
static BAD_3: Schema = Schema {
    number: 2,
    previous: Some(&SCHEMA_1),
    added: REQUIRED,
};
static BAD_4: Schema = Schema {
    number: 2,
    previous: Some(&SCHEMA_1),
    added: GATE_OUTSIDE_RANGE,
};
static BAD_5: Schema = Schema {
    number: 2,
    previous: Some(&SCHEMA_1),
    added: PARAM_IN_GATE_RANGE,
};
static BAD_6: Schema = Schema {
    number: 3,
    previous: Some(&SCHEMA_1),
    added: TEST_ADDED,
};
/// A gate registered in a schema but unknown to `ChainParams`: its value
/// cannot be computed, so building refuses rather than commit an absence.
const UNKNOWN_GATE: &[AddedField] = &[AddedField {
    spec: example_spec(0x1ffd, "no_such_gate_enabled_from_height", true),
    source: Source::Gate,
}];
static UNKNOWN_GATE_SCHEMA: Schema = Schema {
    number: 2,
    previous: Some(&SCHEMA_1),
    added: UNKNOWN_GATE,
};

static UNKNOWN_GATE_POLICY: SchemaPolicy = SchemaPolicy {
    reads: &[&SCHEMA_1, &UNKNOWN_GATE_SCHEMA],
    writes: &UNKNOWN_GATE_SCHEMA,
    knows: &UNKNOWN_GATE_SCHEMA,
};

#[test]
fn a_malformed_registry_refuses_to_build() {
    for bad in [&BAD_1, &BAD_2, &BAD_3, &BAD_4, &BAD_5, &BAD_6] {
        assert!(bad.check().is_err(), "{:?}", bad.added[0].spec.name);
        let policy = Box::leak(Box::new(SchemaPolicy {
            reads: Box::leak(Box::new([&SCHEMA_1 as &'static Schema])),
            writes: &SCHEMA_1,
            knows: bad,
        }));
        assert!(matches!(
            ccfg::build_with(&g0(), policy),
            Err(ConfigError::Build(_))
        ));
    }
    UNKNOWN_GATE_SCHEMA.check().unwrap();
    let policy = &UNKNOWN_GATE_POLICY;
    assert!(ccfg::build_with(&g0(), policy).is_err());
}

/// The test schema encodes and decodes under the same strict rules as
/// schema 1, and its added field is bound by the commitment.
#[test]
fn a_schema_2_encoding_round_trips_and_binds_its_added_field() {
    set_example(Some(9));
    let c = ccfg::build_with(&g2(), &ENABLED).unwrap();
    let bytes = c.encode();
    assert_eq!(u16::from_le_bytes([bytes[7], bytes[8]]), 2);
    assert_eq!(
        ConsensusConfig::decode_with(&bytes, ENABLED.reads).unwrap(),
        c
    );
    assert_eq!(
        ConsensusConfig::decode(&bytes),
        Err(ConfigError::UnknownSchema(2))
    );
    set_example(Some(10));
    assert_ne!(
        ccfg::build_with(&g2(), &ENABLED).unwrap().commitment(),
        c.commitment()
    );
    // A schema-2 encoding missing its added field is refused.
    let schema_1_bytes = ccfg::build(&g2()).unwrap().encode();
    let mut forged = schema_1_bytes.clone();
    forged[7..9].copy_from_slice(&2u16.to_le_bytes());
    assert!(matches!(
        ConsensusConfig::decode_with(&forged, ENABLED.reads),
        Err(ConfigError::Malformed(_))
    ));
    set_example(None);
}

// ── #277's gate on a released schema-1 database ─────────────────────────────

/// Id of `credential_schema_validation_enabled_from_height` (#277).
const CREDENTIAL_GATE: u16 = 0x103f;

fn with_credential_gate(h: Option<u64>) -> Genesis {
    let mut g = g2();
    g.params.credential_schema_validation_enabled_from_height = h;
    g
}

/// The upgrade path for #277's gate, from the schema-1 record a released
/// binary wrote:
///
/// * dormant, this binary starts on it and rewrites nothing, under the
///   production policy and under a policy with the real schema 2 enabled;
/// * set, the production binary refuses (it records schema 1), and a
///   schema-2 binary refuses too, naming the schema transition, until the
///   operator moves the record explicitly;
/// * after the move, the same genesis is accepted at start as an ordinary gate
///   reschedule of 0x103f alone, recorded in the history after the schema-1
///   entries, which stay as they were;
/// * a height the chain has already passed is refused, as for every gate.
#[test]
fn the_credential_gate_on_a_schema_1_database_waits_for_the_schema_transition() {
    let ahead = HEIGHT + 1_000;
    let (_d, db) = schema_1_database();

    // Dormant: unchanged, under both policies.
    let dormant = with_credential_gate(None);
    assert_eq!(
        ccfg::check_at_startup(&db, &dormant, HEIGHT).unwrap(),
        StartupOutcome::Unchanged { commitment: h(C2) }
    );
    assert_eq!(
        check_at_startup_with(&db, &dormant, HEIGHT, &REAL_ENABLED).unwrap(),
        StartupOutcome::Unchanged { commitment: h(C2) }
    );
    assert_eq!(entries(&db), fixture_entries());

    // Set: the production binary cannot record it.
    let set = with_credential_gate(Some(ahead));
    let err = ccfg::check_at_startup(&db, &set, HEIGHT).unwrap_err();
    assert!(matches!(err, ConfigError::Refused(_)), "{err}");
    assert!(
        err.to_string()
            .contains("credential_schema_validation_enabled_from_height"),
        "{err}"
    );
    assert_eq!(entries(&db), fixture_entries());

    // Set, schema 2 enabled, record still schema 1: refused, naming the move.
    let new = moved_commitment(&db, &REAL_ENABLED);
    let err = check_at_startup_with(&db, &set, HEIGHT, &REAL_ENABLED).unwrap_err();
    assert!(matches!(err, ConfigError::Refused(_)), "{err}");
    assert!(
        err.to_string()
            .contains("acknowledge-consensus-config-schema"),
        "{err}"
    );
    let computed = ccfg::build_with(&set, &REAL_ENABLED).unwrap().commitment();
    let err = acknowledge_with(&db, &set, HEIGHT, h(C2), computed, &REAL_ENABLED).unwrap_err();
    assert!(err.to_string().contains("schema 1 cannot express"), "{err}");
    assert_eq!(entries(&db), fixture_entries());

    // The explicit move: 0x103f arrives absent; the history is kept.
    let moved = acknowledge_schema_transition_with(&db, HEIGHT, h(C2), new, &REAL_ENABLED).unwrap();
    assert!(moved.added.contains(&CREDENTIAL_GATE), "{:?}", moved.added);
    let r = read_record_with(&db, &REAL_ENABLED).unwrap().unwrap();
    assert_eq!(r.config.get(CREDENTIAL_GATE), Some(&Value::Absent));
    let fixture = fixture_entries();
    let after = entries(&db);
    assert_eq!(after[1..3], fixture[1..3], "schema-1 history untouched");

    // A passed height is still refused after the move.
    let passed = with_credential_gate(Some(HEIGHT));
    let err = check_at_startup_with(&db, &passed, HEIGHT, &REAL_ENABLED).unwrap_err();
    assert!(err.to_string().contains("already passed"), "{err}");

    // A future height is now an ordinary gate reschedule of 0x103f alone.
    let out = check_at_startup_with(&db, &set, HEIGHT, &REAL_ENABLED).unwrap();
    let StartupOutcome::GatesRescheduled { from, to, changes } = out else {
        panic!("expected a gate reschedule, got {out:?}");
    };
    assert_eq!((from, to), (new, computed));
    assert_eq!(changes.len(), 1, "{changes:?}");
    assert_eq!(changes[0].id, CREDENTIAL_GATE);
    assert_eq!(
        (&changes[0].from, &changes[0].to),
        (&Value::Absent, &Value::U64(ahead))
    );
    let history = read_transitions_with(&db, &REAL_ENABLED).unwrap();
    let kinds: Vec<_> = history.iter().map(|t| t.kind).collect();
    assert_eq!(
        kinds,
        [
            TransitionKind::GateReschedule,
            TransitionKind::OperatorAcknowledged,
            TransitionKind::SchemaTransition,
            TransitionKind::GateReschedule,
        ]
    );
    assert_eq!(history[3].changed_ids, vec![CREDENTIAL_GATE]);
    assert_eq!(
        check_at_startup_with(&db, &set, HEIGHT, &REAL_ENABLED).unwrap(),
        StartupOutcome::Unchanged {
            commitment: computed
        }
    );
}
