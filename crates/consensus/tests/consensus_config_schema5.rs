//! ConsensusConfig schema 5 (#268): schema 4 plus exactly three optional
//! fields, which this binary writes: the two messaging gates (0x1048, 0x1049)
//! and the compiled envelope tag the first of them reads (0x252b), committed
//! only while that gate is set.
//!
//! Every upgrade test starts from `tests/data/consensus_config_schema1_db.tsv`:
//! the exact `cf::META` entries the schema-1 release writes, loaded into a
//! fresh database byte for byte. A schema-2, schema-3 or schema-4 database is
//! that one moved by the release that wrote that schema. The production-shaped
//! databases are the schema-1 one moved to schema 3 in one step and then given
//! the peer-declaration deadline and the node-registry gate as one future-gate
//! reschedule (the history a node that ran the schema-3 releases records), and
//! that database
//! moved on to schema 4 by the release that wrote schema 4
//! ([`SCHEMA_4_RELEASE`]).
//!
//! What an operator relies on, in order:
//!
//! * installing this binary changes nothing: a record of schema 1 to 4 runs as
//!   it stands, compared in its own schema, never re-encoded at start, and
//!   nothing is written;
//! * neither messaging gate can be set until the record is schema 5: before
//!   the move, a genesis that sets them refuses start and names the exact
//!   stopped-node command, both commitments included;
//! * the move is one step from schema 1, 2, 3 or 4, re-encodes the recorded
//!   rules, changes none, keeps the older encoding in the history, and writes
//!   exactly two keys — the record and one transition — in one batch;
//! * the move refuses, and writes nothing, on a wrong commitment, a record
//!   already in schema 5, a damaged record and a record of a schema this
//!   binary does not implement;
//! * after the move, setting the two gates at one future height also commits
//!   the envelope tag, which is not a gate: start refuses and names
//!   `acknowledge-consensus-config`, and the acknowledgement records all three
//!   together; a height already reached is refused;
//! * before the node first starts on the moved record, the move reverts to the
//!   exact rows it replaced; after that, recovery is forward only;
//! * the releases that wrote schemas 1 to 4 refuse a schema-5 record and
//!   rewrite nothing.

use std::collections::BTreeMap;

use sumchain_consensus::consensus_config::{
    self as ccfg,
    codec::commitment_of,
    record::{
        acknowledge_schema_transition_with, acknowledge_with, check_at_startup_with,
        pending_schema_transition_with, read_record_with, read_transitions_with, RECORD_KEY,
        TRANSITION_PREFIX,
    },
    schema::{SCHEMA_4_ADDED, SCHEMA_5_ADDED, SPONSORED_SEND_V2_TAG_ID},
    ConfigError, ConsensusConfig, SchemaPolicy, Source, StartupOutcome, TransitionKind, Value,
    PRODUCTION, SCHEMA_1, SCHEMA_2, SCHEMA_3, SCHEMA_4, SCHEMA_5,
};
use sumchain_crypto::KeyPair;
use sumchain_genesis::{ChainParams, Genesis, GenesisError};
use sumchain_primitives::Hash;
use sumchain_storage::{cf, db::ALL_CFS, Database};
use tempfile::TempDir;

/// The sponsored-envelope verification gate.
const ENVELOPE: u16 = 0x1048;
const ENVELOPE_NAME: &str = "messaging_sponsored_envelope_verification_enabled_from_height";
/// The messaging fee and nonce accounting gate.
const ACCOUNTING: u16 = 0x1049;
const ACCOUNTING_NAME: &str = "messaging_fee_nonce_accounting_enabled_from_height";
/// The three fields schema 5 adds, in id order.
const FIELD_IDS: [u16; 3] = [ENVELOPE, ACCOUNTING, SPONSORED_SEND_V2_TAG_ID];
/// `peer_protocol_declaration_required_from_height`, a schema-1 gate.
const PEER: u16 = 0x1029;
/// `node_registry_update_status_unsupported_enabled_from_height`, schema 3's.
const NODE_REGISTRY: u16 = 0x1043;
/// `archive_unbonding_own_challenges_enabled_from_height`, schema 4's first.
const ARCHIVE_GATE: u16 = 0x1044;

/// The release before schema 2 (reads and writes schema 1). It is given
/// schema 5 to know because a policy must name every gate `ChainParams`
/// declares to build at all; with those gates unset that adds nothing to the
/// schema-1 record it writes.
static SCHEMA_1_RELEASE: SchemaPolicy = SchemaPolicy {
    reads: &[&SCHEMA_1],
    writes: &SCHEMA_1,
    knows: &SCHEMA_5,
};

/// The release that wrote schema 2.
static SCHEMA_2_RELEASE: SchemaPolicy = SchemaPolicy {
    reads: &[&SCHEMA_1, &SCHEMA_2],
    writes: &SCHEMA_2,
    knows: &SCHEMA_5,
};

/// The releases that wrote schema 3.
static SCHEMA_3_RELEASE: SchemaPolicy = SchemaPolicy {
    reads: &[&SCHEMA_1, &SCHEMA_2, &SCHEMA_3],
    writes: &SCHEMA_3,
    knows: &SCHEMA_5,
};

/// The release that wrote schema 4: it read schemas 1 to 4, wrote 4, and knew
/// schema 5 only as a draft whose fields must stay absent.
static SCHEMA_4_RELEASE: SchemaPolicy = SchemaPolicy {
    reads: &[&SCHEMA_1, &SCHEMA_2, &SCHEMA_3, &SCHEMA_4],
    writes: &SCHEMA_4,
    knows: &SCHEMA_5,
};

// ── the fixtures ────────────────────────────────────────────────────────────

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

/// A schema-3 node's record genesis: [`g2`] with the peer-declaration
/// deadline and the node-registry gate scheduled.
fn g_ph() -> Genesis {
    let mut g = g2();
    g.params.peer_protocol_declaration_required_from_height = Some(P);
    g.params
        .node_registry_update_status_unsupported_enabled_from_height = Some(H_GATE);
    g
}

/// The heights [`g_ph`] schedules: both have passed by [`HEAD`].
const P: u64 = 30;
const H_GATE: u64 = 40;

/// [`g_ph`] with both messaging gates at `at`, as genesis validation
/// requires (one height, the peer deadline at or below it).
fn with_messaging_gates(at: u64) -> Genesis {
    let mut g = g_ph();
    g.params
        .messaging_sponsored_envelope_verification_enabled_from_height = Some(at);
    g.params.messaging_fee_nonce_accounting_enabled_from_height = Some(at);
    g
}

/// Height of the fixture's last write.
const HEIGHT: u64 = 20;
/// Height at which the schema-4 release moved the production-shaped database.
const MOVED_TO_4: u64 = 45;
/// Height of the production-shaped databases' head: P and H have passed.
const HEAD: u64 = 50;

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

/// `db` moved at `height` by `policy`, a release that writes its schema.
fn move_with(db: &Database, height: u64, policy: &SchemaPolicy) {
    let p = pending_schema_transition_with(db, policy).unwrap().unwrap();
    acknowledge_schema_transition_with(db, height, p.old, p.new, policy).unwrap();
    assert_eq!(
        read_record_with(db, policy)
            .unwrap()
            .unwrap()
            .config
            .schema()
            .number,
        policy.writes.number
    );
}

/// The schema-1 fixture moved by `policy`, a release that writes its schema.
fn moved_by(policy: &SchemaPolicy) -> (TempDir, Database) {
    let (dir, db) = schema_1_database();
    move_with(&db, HEIGHT, policy);
    (dir, db)
}

fn schema_2_database() -> (TempDir, Database) {
    moved_by(&SCHEMA_2_RELEASE)
}

fn schema_3_database() -> (TempDir, Database) {
    moved_by(&SCHEMA_3_RELEASE)
}

fn schema_4_database() -> (TempDir, Database) {
    moved_by(&SCHEMA_4_RELEASE)
}

/// The schema-3 database a schema-3 release then started under [`g_ph`]: the
/// history ends `schema-transition`, `gate-reschedule`.
fn production_shaped_database() -> (TempDir, Database) {
    let (dir, db) = schema_3_database();
    let out = check_at_startup_with(&db, &g_ph(), HEIGHT, &SCHEMA_3_RELEASE).unwrap();
    assert!(
        matches!(out, StartupOutcome::GatesRescheduled { .. }),
        "{out:?}"
    );
    (dir, db)
}

/// [`production_shaped_database`] moved to schema 4 by the release that wrote
/// schema 4, and started by it: the history ends `schema-transition`,
/// `gate-reschedule`, `schema-transition`.
fn production_shaped_4_database() -> (TempDir, Database) {
    let (dir, db) = production_shaped_database();
    move_with(&db, MOVED_TO_4, &SCHEMA_4_RELEASE);
    assert!(matches!(
        check_at_startup_with(&db, &g_ph(), MOVED_TO_4, &SCHEMA_4_RELEASE).unwrap(),
        StartupOutcome::Unchanged { .. }
    ));
    let kinds: Vec<&str> = read_transitions_with(&db, &SCHEMA_4_RELEASE)
        .unwrap()
        .iter()
        .map(|t| t.kind.label())
        .collect();
    assert_eq!(
        &kinds[kinds.len() - 3..],
        ["schema-transition", "gate-reschedule", "schema-transition"]
    );
    (dir, db)
}

/// Every row of every column family.
fn all_rows(db: &Database) -> BTreeMap<(String, Vec<u8>), Vec<u8>> {
    let mut out = BTreeMap::new();
    for name in ALL_CFS {
        for (k, v) in db.iter(name).unwrap() {
            out.insert((name.to_string(), k.to_vec()), v.to_vec());
        }
    }
    out
}

/// The rows that differ between two snapshots.
fn changed_rows(
    before: &BTreeMap<(String, Vec<u8>), Vec<u8>>,
    after: &BTreeMap<(String, Vec<u8>), Vec<u8>>,
) -> Vec<(String, Vec<u8>)> {
    after
        .keys()
        .chain(before.keys())
        .filter(|k| before.get(*k) != after.get(*k))
        .cloned()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// This binary's one-step move of `db` to schema 5, with the commitments it
/// offers.
fn move_to_schema_5(db: &Database, height: u64) -> ccfg::SchemaTransitioned {
    let p = ccfg::pending_schema_transition(db).unwrap().unwrap();
    assert_eq!(p.to_schema, 5);
    ccfg::acknowledge_schema_transition(db, height, p.old, p.new).unwrap()
}

fn ids(changes: &[ccfg::FieldChange]) -> Vec<u16> {
    let mut v: Vec<u16> = changes.iter().map(|c| c.id).collect();
    v.sort();
    v
}

fn tamper(db: &Database, key: &[u8], f: impl FnOnce(&mut Vec<u8>)) {
    let mut raw = db.get(cf::META, key).unwrap().unwrap();
    f(&mut raw);
    db.put(cf::META, key, &raw).unwrap();
}

fn transition_key(seq: u64) -> Vec<u8> {
    let mut k = TRANSITION_PREFIX.to_vec();
    k.extend_from_slice(&seq.to_be_bytes());
    k
}

/// Re-label a record as `schema`, with a commitment that matches its bytes: a
/// well-formed record of a schema this binary may lack.
fn relabel(db: &Database, schema: u16) {
    tamper(db, RECORD_KEY, |r| {
        r[87 + 7..87 + 9].copy_from_slice(&schema.to_le_bytes());
        let c = commitment_of(&r[87..]);
        r[11..43].copy_from_slice(c.as_bytes());
        r[51..83].copy_from_slice(c.as_bytes());
    });
}

// ── schema 5 ────────────────────────────────────────────────────────────────

#[test]
fn schema_5_is_schema_4_plus_the_two_messaging_gates_and_the_tag_and_this_binary_writes_it() {
    assert_eq!(SCHEMA_5.number, 5);
    assert!(std::ptr::eq(SCHEMA_5.previous.unwrap(), &SCHEMA_4));
    assert_eq!(
        SCHEMA_4_ADDED.len(),
        4,
        "schema 4 is closed at its four gates"
    );
    let added: Vec<(u16, &str)> = SCHEMA_5_ADDED
        .iter()
        .map(|a| (a.spec.id, a.spec.name))
        .collect();
    assert_eq!(
        added,
        [
            (ENVELOPE, ENVELOPE_NAME),
            (ACCOUNTING, ACCOUNTING_NAME),
            (
                SPONSORED_SEND_V2_TAG_ID,
                "sumchain_wire::messaging::SPONSORED_SEND_V2_TAG"
            ),
        ]
    );
    for a in &SCHEMA_5_ADDED[..2] {
        assert!(matches!(a.source, Source::Gate), "{}", a.spec.name);
        assert!(a.spec.optional, "{}", a.spec.name);
        assert_eq!(ccfg::fields::gate_id(a.spec.name), Some(a.spec.id));
    }
    let tag = &SCHEMA_5_ADDED[2];
    assert!(matches!(tag.source, Source::Param(_)));
    assert!(tag.spec.optional);
    assert_eq!(tag.spec.ty, ccfg::fields::Ty::Bytes);
    assert_eq!(SCHEMA_5.specs().len(), SCHEMA_4.specs().len() + 3);
    assert_eq!(SCHEMA_5.added_since(&SCHEMA_4).len(), 3);

    assert!(std::ptr::eq(PRODUCTION.writes, &SCHEMA_5));
    assert!(std::ptr::eq(PRODUCTION.knows, &SCHEMA_5), "no draft field");
    assert_eq!(
        PRODUCTION
            .reads
            .iter()
            .map(|s| s.number)
            .collect::<Vec<_>>(),
        [1, 2, 3, 4, 5],
        "older schemas are read for good"
    );
    for p in [
        &PRODUCTION,
        &SCHEMA_1_RELEASE,
        &SCHEMA_2_RELEASE,
        &SCHEMA_3_RELEASE,
        &SCHEMA_4_RELEASE,
    ] {
        p.check().unwrap();
    }

    // Unset in every default: declaring the fields schedules nothing.
    for params in [
        ChainParams::default(),
        ChainParams::with_contracts_enabled(),
    ] {
        assert_eq!(
            params.messaging_sponsored_envelope_verification_enabled_from_height,
            None
        );
        assert_eq!(
            params.messaging_fee_nonce_accounting_enabled_from_height,
            None
        );
    }
    let c = ccfg::build(&g2()).unwrap();
    for id in FIELD_IDS {
        assert_eq!(c.get(id), Some(&Value::Absent), "{id:#06x}");
    }
}

/// No tracked genesis file or template sets either messaging gate: each is
/// absent from the file or `null`.
#[test]
fn no_tracked_genesis_or_template_sets_a_schema_5_gate() {
    fn walk(dir: &std::path::Path, root: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let p = entry.unwrap().path();
            let name = p.file_name().unwrap().to_string_lossy().to_string();
            if p.is_dir() {
                if p != root.join("devnet")
                    && !matches!(name.as_str(), "target" | ".git" | "node_modules")
                {
                    walk(&p, root, out);
                }
            } else if name.contains("genesis") && name.ends_with(".json") {
                out.push(p);
            }
        }
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let mut files = Vec::new();
    walk(&root, &root, &mut files);
    assert!(files.len() >= 9, "{files:?}");
    for f in files {
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&f).unwrap()).unwrap();
        for name in [ENVELOPE_NAME, ACCOUNTING_NAME] {
            let set = v
                .get("params")
                .and_then(|p| p.get(name))
                .is_some_and(|x| !x.is_null());
            assert!(!set, "{}: {name} is set", f.display());
        }
    }
}

#[test]
fn a_fresh_database_records_schema_5_directly() {
    let dir = TempDir::new().unwrap();
    let db = Database::open_default(dir.path()).unwrap();
    let expected = ccfg::build(&g2()).unwrap();
    assert_eq!(expected.schema().number, 5);
    assert_eq!(
        ccfg::check_at_startup(&db, &g2(), 0).unwrap(),
        StartupOutcome::Initialized {
            commitment: expected.commitment(),
            baseline_height: 0
        }
    );
    let r = ccfg::read_record(&db).unwrap().unwrap();
    assert_eq!(r.config, expected);
    assert_eq!(r.transition_count, 0);
    assert_eq!(ccfg::pending_schema_transition(&db).unwrap(), None);
    // And it is the schema-4 configuration plus the three fields, absent.
    assert_eq!(
        ccfg::build_with(&g2(), &SCHEMA_4_RELEASE)
            .unwrap()
            .extend_to(&SCHEMA_5)
            .unwrap(),
        expected
    );
}

/// The genesis rule this binary keeps: the two gates are both unset or both
/// at one height. Set apart, genesis validation refuses before any
/// configuration is computed; set together, this binary computes them and
/// the tag.
#[test]
fn the_two_gates_are_set_together_or_not_at_all() {
    let mut apart = g_ph();
    apart
        .params
        .messaging_sponsored_envelope_verification_enabled_from_height = Some(HEAD + 100);
    assert!(matches!(
        apart.validate(),
        Err(GenesisError::MessagingEnvelopeAndAccountingGatesApart { .. })
    ));
    let mut apart = g_ph();
    apart
        .params
        .messaging_fee_nonce_accounting_enabled_from_height = Some(HEAD + 100);
    assert!(matches!(
        apart.validate(),
        Err(GenesisError::MessagingEnvelopeAndAccountingGatesApart { .. })
    ));

    let g = with_messaging_gates(HEAD + 100);
    g.validate().unwrap();
    let c = ccfg::build(&g).unwrap();
    assert_eq!(c.get(ENVELOPE), Some(&Value::U64(HEAD + 100)));
    assert_eq!(c.get(ACCOUNTING), Some(&Value::U64(HEAD + 100)));
    assert_eq!(
        c.get(SPONSORED_SEND_V2_TAG_ID),
        Some(&Value::Bytes(
            sumchain_primitives::SPONSORED_SEND_V2_TAG.to_vec()
        ))
    );
    // Without a peer deadline at or below them, validation refuses too.
    let mut no_peer = g0();
    no_peer.validate().unwrap();
    no_peer
        .params
        .messaging_sponsored_envelope_verification_enabled_from_height = Some(HEAD + 100);
    no_peer
        .params
        .messaging_fee_nonce_accounting_enabled_from_height = Some(HEAD + 100);
    assert!(matches!(
        no_peer.validate(),
        Err(GenesisError::RemediationGateWithoutPeerProtocolEnforcement { .. })
    ));
}

// ── installing the binary changes nothing ───────────────────────────────────

/// A database of schema 1 to 4, or production-shaped in schema 3 or 4, runs as
/// it stands, however often this binary starts, nothing is written, and the
/// move straight to schema 5 is offered.
#[test]
fn older_databases_run_as_they_stand_and_are_offered_schema_5_in_one_step() {
    for (label, from, g, (_d, db)) in [
        ("schema 1", 1, g2(), schema_1_database()),
        ("schema 2", 2, g2(), schema_2_database()),
        ("schema 3", 3, g2(), schema_3_database()),
        ("schema 4", 4, g2(), schema_4_database()),
        (
            "production-shaped 3",
            3,
            g_ph(),
            production_shaped_database(),
        ),
        (
            "production-shaped 4",
            4,
            g_ph(),
            production_shaped_4_database(),
        ),
    ] {
        let before = all_rows(&db);
        let r = ccfg::read_record(&db).unwrap().unwrap();
        assert_eq!(r.config.schema().number, from, "{label}");
        for _ in 0..3 {
            assert_eq!(
                ccfg::check_at_startup(&db, &g, HEAD).unwrap(),
                StartupOutcome::Unchanged {
                    commitment: r.commitment
                },
                "{label}"
            );
        }
        assert_eq!(all_rows(&db), before, "{label}: nothing written at start");
        let p = ccfg::pending_schema_transition(&db).unwrap().unwrap();
        assert_eq!((p.from_schema, p.to_schema), (from, 5), "{label}");
        assert_eq!(p.old, r.commitment, "{label}");
        assert_eq!(
            p.new,
            r.config.extend_to(&SCHEMA_5).unwrap().commitment(),
            "{label}"
        );
    }
}

// ── the move ────────────────────────────────────────────────────────────────

/// One step from schema 1, 2, 3 or 4: every field the newer schemas add is
/// recorded absent, the history keeps every earlier entry and gains one schema
/// transition listing exactly the added fields, the moved record runs
/// unchanged, and all four land on the same commitment: the same rules.
#[test]
fn the_one_step_move_keeps_the_rules_and_the_history() {
    let mut landed = Vec::new();
    for (label, from, (_d, db)) in [
        ("schema 1", &SCHEMA_1, schema_1_database()),
        ("schema 2", &SCHEMA_2, schema_2_database()),
        ("schema 3", &SCHEMA_3, schema_3_database()),
        ("schema 4", &SCHEMA_4, schema_4_database()),
    ] {
        let old_history = ccfg::read_transitions(&db).unwrap();
        let old = ccfg::read_record(&db).unwrap().unwrap();
        let done = move_to_schema_5(&db, HEIGHT);
        assert_eq!((done.from_schema, done.to_schema), (from.number, 5));
        assert_eq!(done.from, old.commitment);
        let expected_added: Vec<u16> = SCHEMA_5.added_since(from).iter().map(|s| s.id).collect();
        assert_eq!(done.added, expected_added, "{label}");

        let r = ccfg::read_record(&db).unwrap().unwrap();
        assert_eq!(r.config.schema().number, 5);
        assert_eq!(r.commitment, done.to);
        assert_eq!(r.config, old.config.extend_to(&SCHEMA_5).unwrap());
        for id in &expected_added {
            assert_eq!(r.config.get(*id), Some(&Value::Absent), "{label} {id:#06x}");
        }
        assert_eq!(r.baseline_height, old.baseline_height);
        assert_eq!(r.initial_commitment, old.initial_commitment);
        assert_eq!(r.transition_count, old.transition_count + 1);

        let history = ccfg::read_transitions(&db).unwrap();
        assert_eq!(history.len(), old_history.len() + 1, "{label}");
        assert_eq!(&history[..old_history.len()], &old_history[..], "{label}");
        let last = history.last().unwrap();
        assert_eq!(last.kind, TransitionKind::SchemaTransition);
        assert_eq!(last.at_height, HEIGHT);
        assert_eq!(last.old_commitment, old.commitment);
        assert_eq!(last.new_commitment, done.to);
        assert_eq!(last.old_encoding, old.config.encode(), "{label}: kept");
        assert_eq!(last.changed_ids, expected_added);

        assert_eq!(
            ccfg::check_at_startup(&db, &g2(), HEIGHT).unwrap(),
            StartupOutcome::Unchanged {
                commitment: done.to
            },
            "{label}"
        );
        assert_eq!(ccfg::pending_schema_transition(&db).unwrap(), None);
        landed.push(done.to);
    }
    assert!(landed.windows(2).all(|w| w[0] == w[1]), "{landed:?}");
}

/// The production-shaped schema-4 record moves by exactly the three fields;
/// the production-shaped schema-3 record by schema 4's four gates and those
/// three, in one step. Either way the scheduled peer deadline and
/// node-registry gate are kept, the history gains one schema transition, and
/// the same genesis starts unchanged on the schema-5 configuration this
/// binary computes.
#[test]
fn the_production_shaped_records_move_by_exactly_the_added_fields() {
    for (label, from, expected, (_d, db)) in [
        (
            "production-shaped 4",
            4,
            FIELD_IDS.to_vec(),
            production_shaped_4_database(),
        ),
        (
            "production-shaped 3",
            3,
            vec![
                0x1044,
                0x1045,
                0x1046,
                0x1047,
                ENVELOPE,
                ACCOUNTING,
                SPONSORED_SEND_V2_TAG_ID,
            ],
            production_shaped_database(),
        ),
    ] {
        let old = ccfg::read_record(&db).unwrap().unwrap();
        let done = move_to_schema_5(&db, HEAD);
        assert_eq!((done.from_schema, done.to_schema), (from, 5), "{label}");
        assert_eq!(done.added, expected, "{label}");
        let r = ccfg::read_record(&db).unwrap().unwrap();
        assert_eq!(r.config.get(PEER), Some(&Value::U64(P)), "{label}");
        assert_eq!(
            r.config.get(NODE_REGISTRY),
            Some(&Value::U64(H_GATE)),
            "{label}"
        );
        assert_eq!(
            r.config,
            old.config.extend_to(&SCHEMA_5).unwrap(),
            "{label}"
        );
        let kinds: Vec<&str> = ccfg::read_transitions(&db)
            .unwrap()
            .iter()
            .map(|t| t.kind.label())
            .collect();
        assert_eq!(kinds.last(), Some(&"schema-transition"), "{label}");
        assert_eq!(
            ccfg::check_at_startup(&db, &g_ph(), HEAD).unwrap(),
            StartupOutcome::Unchanged {
                commitment: done.to
            },
            "{label}"
        );
        assert_eq!(r.config, ccfg::build(&g_ph()).unwrap(), "{label}");
    }
}

/// The move writes exactly two rows — the record, replaced, and one new
/// transition — and touches no other row of any column family.
#[test]
fn the_move_writes_only_the_record_and_one_transition() {
    let (_d, db) = production_shaped_4_database();
    let before = all_rows(&db);
    let r = ccfg::read_record(&db).unwrap().unwrap();
    move_to_schema_5(&db, HEAD);
    let next = transition_key(r.transition_count + 1);
    assert_eq!(
        changed_rows(&before, &all_rows(&db)),
        vec![
            (cf::META.to_string(), RECORD_KEY.to_vec()),
            (cf::META.to_string(), next.clone()),
        ]
    );
    assert!(!before.contains_key(&(cf::META.to_string(), next)));
}

/// Once moved there is nothing left to move; a second run refuses with any
/// commitments, and nothing is written.
#[test]
fn a_moved_record_has_nothing_left_to_move_and_a_rerun_writes_nothing() {
    let (_d, db) = production_shaped_4_database();
    let done = move_to_schema_5(&db, HEAD);
    let before = all_rows(&db);
    assert_eq!(ccfg::pending_schema_transition(&db).unwrap(), None);
    for (old, new) in [(done.to, done.to), (done.from, done.to)] {
        let err = ccfg::acknowledge_schema_transition(&db, HEAD, old, new).unwrap_err();
        assert!(
            err.to_string().contains("already recorded in schema 5"),
            "{err}"
        );
    }
    assert_eq!(all_rows(&db), before);
}

/// The move names both commitments exactly; anything else refuses and writes
/// nothing. The refusal of a wrong `--new` names the right one.
#[test]
fn the_move_must_name_both_commitments_exactly() {
    let (_d, db) = production_shaped_4_database();
    let p = ccfg::pending_schema_transition(&db).unwrap().unwrap();
    let zero = Hash::from_hex(&format!("0x{}", "00".repeat(32))).unwrap();
    let before = all_rows(&db);
    for (old, new) in [(zero, p.new), (p.old, zero), (p.new, p.old), (p.old, p.old)] {
        let err = ccfg::acknowledge_schema_transition(&db, HEAD, old, new).unwrap_err();
        assert!(matches!(err, ConfigError::Refused(_)), "{err}");
    }
    let err = ccfg::acknowledge_schema_transition(&db, HEAD, p.old, zero).unwrap_err();
    assert!(err.to_string().contains(&p.new.to_string()), "{err}");
    assert_eq!(all_rows(&db), before);
}

// ── refusals: damaged, unknown, disagreeing ─────────────────────────────────

type Damage = Box<dyn Fn(&Database)>;

/// A damaged record or history is refused by the move, by the offer of the
/// move and by start, and none of them writes anything or repairs it.
#[test]
fn a_damaged_record_is_refused_by_the_move_and_nothing_is_written() {
    let cases: Vec<(&str, Damage)> = vec![
        (
            "flipped encoding byte",
            Box::new(|db| tamper(db, RECORD_KEY, |r| *r.last_mut().unwrap() ^= 1)),
        ),
        (
            "flipped commitment byte",
            Box::new(|db| tamper(db, RECORD_KEY, |r| r[60] ^= 1)),
        ),
        (
            "truncated record",
            Box::new(|db| tamper(db, RECORD_KEY, |r| r.truncate(r.len() - 3))),
        ),
        (
            "a transition missing",
            Box::new(|db| db.delete(cf::META, &transition_key(1)).unwrap()),
        ),
        (
            "the schema-4 move's kept encoding damaged",
            Box::new(|db| {
                let n = ccfg::read_record(db).unwrap().unwrap().transition_count;
                tamper(db, &transition_key(n), |t| *t.last_mut().unwrap() ^= 1)
            }),
        ),
    ];
    for (what, damage) in cases {
        let (_d, db) = production_shaped_4_database();
        let p = ccfg::pending_schema_transition(&db).unwrap().unwrap();
        damage(&db);
        let before = all_rows(&db);
        let err = ccfg::acknowledge_schema_transition(&db, HEAD, p.old, p.new).unwrap_err();
        assert!(
            matches!(err, ConfigError::RecordCorrupt(_)),
            "{what}: {err}"
        );
        assert!(ccfg::pending_schema_transition(&db).is_err(), "{what}");
        assert!(
            ccfg::check_at_startup(&db, &g_ph(), HEAD).is_err(),
            "{what}"
        );
        assert_eq!(all_rows(&db), before, "{what}: nothing written");
    }
}

/// A record whose encoding declares schema 6 — a binary this one predates —
/// is refused as written by a newer binary, by the move and by start, and
/// nothing is written.
#[test]
fn a_record_of_an_unknown_future_schema_is_refused_and_nothing_is_written() {
    let dir = TempDir::new().unwrap();
    let db = Database::open_default(dir.path()).unwrap();
    ccfg::check_at_startup(&db, &g2(), 0).unwrap();
    relabel(&db, 6);
    let raw = db.get(cf::META, RECORD_KEY).unwrap().unwrap();
    assert_eq!(
        ConsensusConfig::decode(&raw[87..]),
        Err(ConfigError::UnknownSchema(6))
    );
    let before = all_rows(&db);
    let err = ccfg::read_record(&db).unwrap_err();
    assert!(matches!(err, ConfigError::RecordCorrupt(_)), "{err}");
    assert!(err.to_string().contains("schema 6"), "{err}");
    assert!(err.to_string().contains("newer binary"), "{err}");
    let c = commitment_of(&raw[87..]);
    let err = ccfg::acknowledge_schema_transition(&db, 0, c, c).unwrap_err();
    assert!(err.to_string().contains("newer binary"), "{err}");
    assert!(ccfg::pending_schema_transition(&db).is_err());
    assert!(ccfg::check_at_startup(&db, &g2(), 0).is_err());
    assert!(ccfg::pending_schema_revert(&db).is_err());
    assert_eq!(all_rows(&db), before, "nothing written");
}

/// The move consults no genesis. A record that disagrees with the node's
/// genesis in a rule refuses start before the move, naming the field and the
/// field-level acknowledgement; the move still re-encodes the record exactly;
/// and after it start refuses the same way, naming the same field.
#[test]
fn a_record_that_disagrees_with_the_genesis_is_refused_before_and_after_the_move() {
    let (_d, db) = production_shaped_4_database();
    let mut other = g_ph();
    other.params.max_contract_gas += 1;
    let field = ccfg::fields::SCHEMA_V1_FIELDS
        .iter()
        .find(|s| s.name == "max_contract_gas")
        .unwrap()
        .id;

    let refused = |db: &Database| {
        let before = all_rows(db);
        let err = ccfg::check_at_startup(db, &other, HEAD).unwrap_err();
        let text = err.to_string();
        assert!(matches!(err, ConfigError::Refused(_)), "{text}");
        assert!(text.contains("max_contract_gas"), "{text}");
        assert!(
            text.contains("acknowledge-consensus-config --old"),
            "{text}"
        );
        assert_eq!(all_rows(db), before, "nothing written");
        let r = ccfg::read_record(db).unwrap().unwrap();
        let computed = ccfg::build_with(
            &other,
            match r.config.schema().number {
                4 => &SCHEMA_4_RELEASE,
                _ => &PRODUCTION,
            },
        )
        .unwrap();
        ids(&r.config.diff(&computed).unwrap())
    };
    assert_eq!(refused(&db), vec![field], "before the move");
    let done = move_to_schema_5(&db, HEAD);
    assert_eq!(ccfg::read_record(&db).unwrap().unwrap().commitment, done.to);
    assert_eq!(refused(&db), vec![field], "after the move: the same field");
}

// ── ordering: the gates wait for the move ───────────────────────────────────

/// Before the move, a genesis that sets the two messaging gates — at one
/// height, with the peer deadline at or below it, as genesis validation
/// requires — refuses start and names the stopped-node command with both
/// commitments; the field-level acknowledgement refuses too. Nothing is
/// written, on every older database alike. Unset again, the node starts
/// unchanged.
#[test]
fn before_the_move_setting_the_messaging_gates_refuses_and_names_the_command() {
    for (label, base, (_d, db)) in [
        ("schema 1", g2(), schema_1_database()),
        ("schema 2", g2(), schema_2_database()),
        ("schema 3", g2(), schema_3_database()),
        ("schema 4", g2(), schema_4_database()),
        ("production-shaped 3", g_ph(), production_shaped_database()),
        (
            "production-shaped 4",
            g_ph(),
            production_shaped_4_database(),
        ),
    ] {
        let before = all_rows(&db);
        let r = ccfg::read_record(&db).unwrap().unwrap();
        let p = ccfg::pending_schema_transition(&db).unwrap().unwrap();
        let mut g = base.clone();
        g.params.peer_protocol_declaration_required_from_height = base
            .params
            .peer_protocol_declaration_required_from_height
            .or(Some(HEAD + 100));
        g.params
            .messaging_sponsored_envelope_verification_enabled_from_height = Some(HEAD + 200);
        g.params.messaging_fee_nonce_accounting_enabled_from_height = Some(HEAD + 200);
        g.validate().unwrap();

        let err = ccfg::check_at_startup(&db, &g, HEAD).unwrap_err();
        let text = err.to_string();
        assert!(matches!(err, ConfigError::Refused(_)), "{label}: {text}");
        assert!(text.contains(ENVELOPE_NAME), "{label}: {text}");
        assert!(text.contains(ACCOUNTING_NAME), "{label}: {text}");
        assert!(
            text.contains(&format!(
                "acknowledge-consensus-config-schema --old {} --new {}",
                p.old, p.new
            )),
            "{label}: {text}"
        );
        let ack = ccfg::acknowledge(&db, &g, HEAD, r.commitment, r.commitment).unwrap_err();
        assert!(
            ack.to_string()
                .contains("acknowledge-consensus-config-schema"),
            "{label}: {ack}"
        );
        assert_eq!(all_rows(&db), before, "{label}: nothing written");
        assert_eq!(
            ccfg::check_at_startup(&db, &base, HEAD).unwrap(),
            StartupOutcome::Unchanged {
                commitment: r.commitment
            },
            "{label}"
        );
    }
}

/// After the move, the two gates at a future height move three fields: the
/// heights and the envelope tag committed while the envelope gate is set. The
/// tag is not a gate, so start refuses and names the field-level
/// acknowledgement instead of recording a reschedule; acknowledged, all three
/// are recorded together, and the node starts unchanged. A height already
/// reached is refused, and nothing is written. Unsetting them later moves the
/// tag again, so it is acknowledged the same way.
#[test]
fn after_the_move_the_messaging_gates_are_acknowledged_with_the_tag() {
    let (_d, db) = production_shaped_4_database();
    let moved = move_to_schema_5(&db, HEAD);

    let before = all_rows(&db);
    for at in [HEAD - 1, HEAD] {
        let err = ccfg::check_at_startup(&db, &with_messaging_gates(at), HEAD).unwrap_err();
        assert!(err.to_string().contains("already passed"), "{at}: {err}");
        assert!(err.to_string().contains(ENVELOPE_NAME), "{at}: {err}");
    }
    assert_eq!(all_rows(&db), before, "nothing written");

    let g = with_messaging_gates(HEAD + 100);
    g.validate().unwrap();
    let err = ccfg::check_at_startup(&db, &g, HEAD).unwrap_err();
    assert!(matches!(err, ConfigError::Refused(_)), "{err}");
    let text = err.to_string();
    assert!(text.contains("SPONSORED_SEND_V2_TAG"), "{text}");
    assert!(
        text.contains("acknowledge-consensus-config --old"),
        "{text}"
    );
    assert_eq!(all_rows(&db), before, "nothing recorded");

    let computed = ccfg::build(&g).unwrap().commitment();
    let ack = ccfg::acknowledge(&db, &g, HEAD, moved.to, computed).unwrap();
    assert_eq!(ids(&ack.changes), FIELD_IDS);
    let last = ccfg::read_transitions(&db).unwrap().pop().unwrap();
    assert_eq!(last.kind, TransitionKind::OperatorAcknowledged);
    assert_eq!(last.changed_ids, FIELD_IDS);
    assert_eq!(
        ccfg::check_at_startup(&db, &g, HEAD + 1).unwrap(),
        StartupOutcome::Unchanged {
            commitment: computed
        }
    );

    // Still ahead of the chain: unsetting is allowed, and is acknowledged the
    // same way, because the tag moves back to absent.
    let err = ccfg::check_at_startup(&db, &g_ph(), HEAD + 2).unwrap_err();
    assert!(err.to_string().contains("SPONSORED_SEND_V2_TAG"), "{err}");
    let back = ccfg::build(&g_ph()).unwrap().commitment();
    assert_eq!(back, moved.to);
    ccfg::acknowledge(&db, &g_ph(), HEAD + 2, computed, back).unwrap();
    assert_eq!(
        ccfg::check_at_startup(&db, &g_ph(), HEAD + 3).unwrap(),
        StartupOutcome::Unchanged { commitment: back }
    );
}

/// After the move, a schema-4 gate alone at a future height is still an
/// ordinary future-gate reschedule of exactly that field.
#[test]
fn after_the_move_a_schema_4_gate_is_still_a_future_gate_reschedule() {
    let (_d, db) = production_shaped_4_database();
    let moved = move_to_schema_5(&db, HEAD);
    let mut g = g_ph();
    g.params
        .archive_unbonding_own_challenges_enabled_from_height = Some(HEAD + 100);
    g.validate().unwrap();
    let out = ccfg::check_at_startup(&db, &g, HEAD).unwrap();
    let StartupOutcome::GatesRescheduled { from, changes, .. } = out else {
        panic!("expected a reschedule, got {out:?}");
    };
    assert_eq!(from, moved.to);
    assert_eq!(ids(&changes), vec![ARCHIVE_GATE]);
}

// ── older binaries ──────────────────────────────────────────────────────────

/// The releases that wrote schemas 1 to 4 — the one this binary follows among
/// them — refuse a schema-5 record, moved or fresh, as written by a newer
/// binary, and rewrite nothing. This binary runs it.
#[test]
fn older_releases_refuse_a_schema_5_record_and_rewrite_nothing() {
    let (_d1, moved_from_1) = schema_1_database();
    move_to_schema_5(&moved_from_1, HEIGHT);
    let (_d4, moved_from_ph4) = production_shaped_4_database();
    move_to_schema_5(&moved_from_ph4, HEAD);
    let fresh_dir = TempDir::new().unwrap();
    let fresh = Database::open_default(fresh_dir.path()).unwrap();
    ccfg::check_at_startup(&fresh, &g2(), 0).unwrap();

    for (label, db, g) in [
        ("moved from schema 1", &moved_from_1, g2()),
        ("moved from production shape 4", &moved_from_ph4, g_ph()),
        ("fresh", &fresh, g2()),
    ] {
        let before = all_rows(db);
        let raw = db.get(cf::META, RECORD_KEY).unwrap().unwrap();
        for (who, policy) in [
            ("schema-1 release", &SCHEMA_1_RELEASE),
            ("schema-2 release", &SCHEMA_2_RELEASE),
            ("schema-3 release", &SCHEMA_3_RELEASE),
            ("schema-4 release", &SCHEMA_4_RELEASE),
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
            assert!(check_at_startup_with(db, &g, HEAD, policy).is_err());
            assert!(read_transitions_with(db, policy).is_err());
            let c = h(C2);
            assert!(acknowledge_with(db, &g, HEAD, c, c, policy).is_err());
            assert!(acknowledge_schema_transition_with(db, HEAD, c, c, policy).is_err());
            assert!(pending_schema_transition_with(db, policy).is_err());
            assert_eq!(
                ConsensusConfig::decode_with(&raw[87..], policy.reads),
                Err(ConfigError::UnknownSchema(5)),
                "{label}, {who}"
            );
            assert_eq!(all_rows(db), before, "{label}, {who}: nothing rewritten");
        }
        assert!(matches!(
            ccfg::check_at_startup(db, &g, HEAD).unwrap(),
            StartupOutcome::Unchanged { .. }
        ));
        assert_eq!(all_rows(db), before, "{label}: nothing rewritten");
    }
}

// ── an interrupted move (in process; the real crash is in the node's tests) ─

/// The record and its transition are one durable batch. A batch staged and
/// lost leaves the old database row for row; the release the node came from
/// starts on it, and the move can be run again.
#[test]
fn a_move_lost_before_the_commit_leaves_the_old_record_and_can_be_retried() {
    let (dir, db) = production_shaped_4_database();
    let before = all_rows(&db);
    let p = ccfg::pending_schema_transition(&db).unwrap().unwrap();
    {
        let r = ccfg::read_record(&db).unwrap().unwrap();
        let mut batch = db.batch();
        batch
            .put(cf::META, &transition_key(r.transition_count + 1), b"staged")
            .unwrap();
        batch.put(cf::META, RECORD_KEY, b"staged").unwrap();
        drop(batch);
    }
    drop(db);
    let db = Database::open_default(dir.path()).unwrap();
    assert_eq!(all_rows(&db), before);
    assert_eq!(
        check_at_startup_with(&db, &g_ph(), HEAD, &SCHEMA_4_RELEASE).unwrap(),
        StartupOutcome::Unchanged { commitment: p.old }
    );
    let done = ccfg::acknowledge_schema_transition(&db, HEAD, p.old, p.new).unwrap();
    assert_eq!(done.to, p.new);
}

/// A database holding only half of a move — which one batch rules out, and
/// only damage can produce — is refused by this binary and by the schema-4
/// release, never repaired or recreated.
#[test]
fn half_a_move_is_refused_and_never_repaired() {
    let (_dm, moved) = production_shaped_4_database();
    let r = ccfg::read_record(&moved).unwrap().unwrap();
    let seq = r.transition_count + 1;
    move_to_schema_5(&moved, HEAD);
    let new_record = moved.get(cf::META, RECORD_KEY).unwrap().unwrap();
    let new_transition = moved.get(cf::META, &transition_key(seq)).unwrap().unwrap();

    for (what, only_record) in [("the transition alone", false), ("the record alone", true)] {
        let (_d, db) = production_shaped_4_database();
        if only_record {
            db.put(cf::META, RECORD_KEY, &new_record).unwrap();
        } else {
            db.put(cf::META, &transition_key(seq), &new_transition)
                .unwrap();
        }
        let before = all_rows(&db);
        for policy in [&PRODUCTION, &SCHEMA_4_RELEASE] {
            let err = check_at_startup_with(&db, &g_ph(), HEAD, policy).unwrap_err();
            assert!(
                matches!(err, ConfigError::RecordCorrupt(_)),
                "{what}: {err}"
            );
            assert!(read_record_with(&db, policy).is_err(), "{what}");
        }
        assert_eq!(all_rows(&db), before, "{what}: nothing written");
    }
}

// ── the pre-start revert ────────────────────────────────────────────────────

/// The chain head this database reports, as a node's blocks would set it.
fn set_head(db: &Database, height: u64) {
    sumchain_storage::schema::BlockStore::new(db)
        .set_latest_height(height)
        .unwrap();
}

/// A block-height index entry at `height`, as an imported block writes one.
fn index_block_at(db: &Database, height: u64) {
    db.put(cf::BLOCK_HEIGHT, &height.to_be_bytes(), &[7u8; 32])
        .unwrap();
}

/// The release that reads `schema` as its newest: the one a node returns to
/// when the move is abandoned.
fn release_writing(schema: u16) -> &'static SchemaPolicy {
    match schema {
        1 => &SCHEMA_1_RELEASE,
        2 => &SCHEMA_2_RELEASE,
        3 => &SCHEMA_3_RELEASE,
        4 => &SCHEMA_4_RELEASE,
        n => panic!("no release writes schema {n}"),
    }
}

/// Before the node first starts on the moved record, the move reverts to the
/// exact rows it replaced — every column family, byte for byte — from every
/// older database. The release the node came from then reads and starts on it
/// unchanged, and this binary offers the same move again.
#[test]
fn before_the_first_start_the_move_reverts_to_exactly_the_old_rows() {
    for (label, from, g, (_d, db)) in [
        ("schema 1", 1, g2(), schema_1_database()),
        ("schema 2", 2, g2(), schema_2_database()),
        ("schema 3", 3, g2(), schema_3_database()),
        ("schema 4", 4, g2(), schema_4_database()),
        (
            "production-shaped 3",
            3,
            g_ph(),
            production_shaped_database(),
        ),
        (
            "production-shaped 4",
            4,
            g_ph(),
            production_shaped_4_database(),
        ),
    ] {
        set_head(&db, HEAD);
        let before = all_rows(&db);
        let r = ccfg::read_record(&db).unwrap().unwrap();
        let offered = ccfg::pending_schema_transition(&db).unwrap().unwrap();
        let moved = move_to_schema_5(&db, HEAD);

        let p = ccfg::pending_schema_revert(&db).unwrap();
        assert_eq!(p.seq, r.transition_count + 1, "{label}");
        assert_eq!(p.at_height, HEAD, "{label}");
        assert_eq!((p.from_schema, p.to_schema), (5, from), "{label}");
        assert_eq!((p.old, p.new), (moved.to, r.commitment), "{label}");

        let done = ccfg::revert_schema_transition(&db, p.old, p.new).unwrap();
        assert_eq!(
            (
                done.seq,
                done.from_schema,
                done.to_schema,
                done.from,
                done.to
            ),
            (p.seq, 5, from, moved.to, r.commitment),
            "{label}"
        );
        assert_eq!(all_rows(&db), before, "{label}: exactly the old rows");

        let old_release = release_writing(from);
        assert_eq!(
            read_record_with(&db, old_release).unwrap().unwrap(),
            r,
            "{label}"
        );
        assert_eq!(
            check_at_startup_with(&db, &g, HEAD, old_release).unwrap(),
            StartupOutcome::Unchanged {
                commitment: r.commitment
            },
            "{label}: the old release starts on it"
        );
        assert_eq!(all_rows(&db), before, "{label}: and writes nothing");
        assert_eq!(
            ccfg::pending_schema_transition(&db).unwrap(),
            Some(offered),
            "{label}: the same move is offered again"
        );
        assert!(ccfg::pending_schema_revert(&db).is_err(), "{label}");
    }
}

/// The revert names both commitments exactly; anything else refuses and
/// writes nothing. The refusal of a wrong `--new` names the right one.
#[test]
fn the_revert_must_name_both_commitments_exactly() {
    let (_d, db) = production_shaped_4_database();
    set_head(&db, HEAD);
    move_to_schema_5(&db, HEAD);
    let p = ccfg::pending_schema_revert(&db).unwrap();
    let zero = Hash::from_hex(&format!("0x{}", "00".repeat(32))).unwrap();
    let before = all_rows(&db);
    for (old, new) in [(zero, p.new), (p.old, zero), (p.new, p.old), (p.old, p.old)] {
        let err = ccfg::revert_schema_transition(&db, old, new).unwrap_err();
        assert!(matches!(err, ConfigError::Refused(_)), "{err}");
    }
    let err = ccfg::revert_schema_transition(&db, p.old, zero).unwrap_err();
    assert!(err.to_string().contains(&p.new.to_string()), "{err}");
    assert_eq!(all_rows(&db), before);
}

/// Once the chain has moved off the height the move was made at, the revert is
/// refused and nothing is written. Recovery is then forward only.
#[test]
fn the_revert_is_refused_once_the_chain_has_moved_past_the_move() {
    type Advance = fn(&Database);
    let cases: [(&str, Advance); 3] = [
        ("one block above, as imported", |db| {
            index_block_at(db, HEAD + 1);
            set_head(db, HEAD + 1);
        }),
        ("an indexed block above an unmoved head", |db| {
            index_block_at(db, HEAD + 3)
        }),
        ("the head below the move", |db| set_head(db, HEAD - 1)),
    ];
    for (what, advance) in cases {
        let (_d, db) = production_shaped_4_database();
        set_head(&db, HEAD);
        index_block_at(&db, HEAD);
        move_to_schema_5(&db, HEAD);
        let p = ccfg::pending_schema_revert(&db).unwrap();
        advance(&db);
        let before = all_rows(&db);
        let err = ccfg::revert_schema_transition(&db, p.old, p.new).unwrap_err();
        assert!(matches!(err, ConfigError::Refused(_)), "{what}: {err}");
        if what != "the head below the move" {
            assert!(err.to_string().contains("forward only"), "{what}: {err}");
        }
        assert_eq!(all_rows(&db), before, "{what}: nothing written");
        assert_eq!(
            ccfg::read_record(&db).unwrap().unwrap().commitment,
            p.old,
            "{what}: still moved"
        );
    }
}

/// Only an unstarted move reverts: a database whose last transition is not
/// this binary's schema transition — a later acknowledgement or reschedule,
/// the schema-4 release's own move, or no transition at all — refuses, and
/// nothing is written.
#[test]
fn the_revert_is_refused_without_an_unstarted_move() {
    // An acknowledgement of the two gates after the move.
    let (_d1, acknowledged) = production_shaped_4_database();
    let moved = move_to_schema_5(&acknowledged, HEAD);
    let g = with_messaging_gates(HEAD + 100);
    let computed = ccfg::build(&g).unwrap().commitment();
    ccfg::acknowledge(&acknowledged, &g, HEAD, moved.to, computed).unwrap();
    // A schema-4 gate rescheduled after the move.
    let (_d2, rescheduled) = production_shaped_4_database();
    move_to_schema_5(&rescheduled, HEAD);
    let mut g = g_ph();
    g.params
        .archive_unbonding_own_challenges_enabled_from_height = Some(HEAD + 100);
    ccfg::check_at_startup(&rescheduled, &g, HEAD).unwrap();
    // The schema-4 release's own move (last transition: a schema transition
    // into schema 4).
    let (_d3, schema_4) = schema_4_database();
    set_head(&schema_4, HEIGHT);
    // A fresh schema-5 record (no transition).
    let fresh_dir = TempDir::new().unwrap();
    let fresh = Database::open_default(fresh_dir.path()).unwrap();
    ccfg::check_at_startup(&fresh, &g2(), 0).unwrap();

    for (what, db, says) in [
        (
            "a later acknowledgement",
            &acknowledged,
            "operator-acknowledged",
        ),
        ("a later reschedule", &rescheduled, "gate-reschedule"),
        (
            "the schema-4 release's move",
            &schema_4,
            "this binary writes schema 5",
        ),
        ("a fresh record", &fresh, "no transition"),
    ] {
        let before = all_rows(db);
        let err = ccfg::pending_schema_revert(db).unwrap_err();
        assert!(matches!(err, ConfigError::Refused(_)), "{what}: {err}");
        assert!(err.to_string().contains(says), "{what}: {err}");
        let c = h(C2);
        assert!(ccfg::revert_schema_transition(db, c, c).is_err(), "{what}");
        assert_eq!(all_rows(db), before, "{what}: nothing written");
    }
}

/// A second revert has nothing to undo; a damaged record is refused as
/// damaged. Nothing is written.
#[test]
fn the_revert_refuses_a_second_run_and_a_damaged_record() {
    let (_d, db) = production_shaped_4_database();
    set_head(&db, HEAD);
    move_to_schema_5(&db, HEAD);
    let p = ccfg::pending_schema_revert(&db).unwrap();
    ccfg::revert_schema_transition(&db, p.old, p.new).unwrap();
    let before = all_rows(&db);
    let err = ccfg::revert_schema_transition(&db, p.old, p.new).unwrap_err();
    assert!(matches!(err, ConfigError::Refused(_)), "{err}");
    assert_eq!(all_rows(&db), before, "a second run writes nothing");

    let (_d2, db) = production_shaped_4_database();
    set_head(&db, HEAD);
    move_to_schema_5(&db, HEAD);
    let p = ccfg::pending_schema_revert(&db).unwrap();
    tamper(&db, RECORD_KEY, |r| *r.last_mut().unwrap() ^= 1);
    let before = all_rows(&db);
    let err = ccfg::revert_schema_transition(&db, p.old, p.new).unwrap_err();
    assert!(matches!(err, ConfigError::RecordCorrupt(_)), "{err}");
    assert_eq!(all_rows(&db), before, "damaged: nothing written");
}

/// The restored record and the removal of the move's transition are one
/// durable batch. A batch staged and lost leaves the moved database row for
/// row, and the revert can be run again; half a revert is refused by this
/// binary and by the schema-4 release, never repaired.
#[test]
fn a_lost_revert_leaves_the_moved_record_and_half_a_revert_is_refused() {
    let (dir, db) = production_shaped_4_database();
    set_head(&db, HEAD);
    let unmoved = all_rows(&db);
    let original = db.get(cf::META, RECORD_KEY).unwrap().unwrap();
    move_to_schema_5(&db, HEAD);
    let p = ccfg::pending_schema_revert(&db).unwrap();
    let moved = all_rows(&db);
    {
        let mut batch = db.batch();
        batch.delete(cf::META, &transition_key(p.seq)).unwrap();
        batch.put(cf::META, RECORD_KEY, &original).unwrap();
        drop(batch);
    }
    drop(db);
    let db = Database::open_default(dir.path()).unwrap();
    assert_eq!(all_rows(&db), moved);
    ccfg::revert_schema_transition(&db, p.old, p.new).unwrap();
    assert_eq!(all_rows(&db), unmoved);

    for what in ["the record restored alone", "the transition removed alone"] {
        let (_d, db) = production_shaped_4_database();
        set_head(&db, HEAD);
        move_to_schema_5(&db, HEAD);
        if what == "the record restored alone" {
            db.put(cf::META, RECORD_KEY, &original).unwrap();
        } else {
            db.delete(cf::META, &transition_key(p.seq)).unwrap();
        }
        let before = all_rows(&db);
        for policy in [&PRODUCTION, &SCHEMA_4_RELEASE] {
            let err = check_at_startup_with(&db, &g_ph(), HEAD, policy).unwrap_err();
            assert!(
                matches!(err, ConfigError::RecordCorrupt(_)),
                "{what}: {err}"
            );
        }
        assert!(ccfg::pending_schema_revert(&db).is_err(), "{what}");
        assert_eq!(all_rows(&db), before, "{what}: nothing written");
    }
}

// ── the start marker across the move from schema 4 ──────────────────────────

use sumchain_consensus::consensus_config::{read_start_marker, record_start, RecordState};

/// A node that ran the schema-4 release on its schema-4 record left a start
/// marker at that record's transition count. Moved to schema 5 and never
/// started since, the move reverts: the marker predates the move. The move
/// writes no marker, and the revert leaves the pre-move marker as it is.
#[test]
fn a_marker_left_by_the_schema_4_release_does_not_block_the_revert() {
    let (_d, db) = production_shaped_4_database();
    set_head(&db, HEAD);
    let pre = record_start(&db).unwrap();
    let r4 = read_record_with(&db, &SCHEMA_4_RELEASE).unwrap().unwrap();
    assert_eq!(
        pre.record,
        RecordState::Present {
            transition_count: r4.transition_count,
            commitment: r4.commitment
        }
    );
    let before = all_rows(&db);
    let moved = move_to_schema_5(&db, HEAD);
    assert_eq!(read_start_marker(&db).unwrap(), Some(pre.clone()));
    let p = ccfg::pending_schema_revert(&db).unwrap();
    assert_eq!(p.start_marker, Some(pre.clone()));
    ccfg::revert_schema_transition(&db, moved.to, moved.from).unwrap();
    assert_eq!(all_rows(&db), before, "every row, the marker included");
}

/// A marker written at the move's own transition count means a node started
/// on the moved record: the revert refuses, whatever else the start did, and
/// writes nothing. Recovery is forward only.
#[test]
fn a_start_on_the_schema_5_record_closes_the_revert_window() {
    let (_d, db) = production_shaped_4_database();
    set_head(&db, HEAD);
    let moved = move_to_schema_5(&db, HEAD);
    assert!(ccfg::pending_schema_revert(&db).is_ok());
    let m = record_start(&db).unwrap();
    assert_eq!(
        m.record,
        RecordState::Present {
            transition_count: moved.seq,
            commitment: moved.to
        }
    );
    let before = all_rows(&db);
    let err = ccfg::revert_schema_transition(&db, moved.to, moved.from).unwrap_err();
    assert!(matches!(err, ConfigError::Refused(_)), "{err}");
    let text = err.to_string();
    assert!(
        text.contains("a normal start was attempted on the moved record"),
        "{text}"
    );
    assert!(text.contains("forward only"), "{text}");
    assert_eq!(all_rows(&db), before, "nothing written");
}

/// A database the schema-4 release created and started exactly once holds a
/// marker written before its first baseline existed. The revert of a move made
/// on it is refused as an uncertain migration state; after one more start of
/// the schema-4 release, the marker records the baseline and the revert is
/// available.
#[test]
fn a_database_started_once_needs_one_more_start_before_the_move() {
    for restarted in [false, true] {
        let dir = TempDir::new().unwrap();
        let db = Database::open_default(dir.path()).unwrap();
        set_head(&db, HEAD);
        // The schema-4 release's first start: the marker, then the baseline.
        let first = record_start(&db).unwrap();
        assert_eq!(first.record, RecordState::Absent);
        check_at_startup_with(&db, &g2(), 0, &SCHEMA_4_RELEASE).unwrap();
        if restarted {
            let second = record_start(&db).unwrap();
            assert!(matches!(second.record, RecordState::Present { .. }));
            check_at_startup_with(&db, &g2(), 0, &SCHEMA_4_RELEASE).unwrap();
        }
        let before = all_rows(&db);
        let moved = move_to_schema_5(&db, HEAD);
        let result = ccfg::revert_schema_transition(&db, moved.to, moved.from);
        if restarted {
            result.unwrap();
            assert_eq!(all_rows(&db), before, "restarted: exactly the old rows");
        } else {
            let err = result.unwrap_err();
            assert!(
                err.to_string().contains("uncertain migration state"),
                "{err}"
            );
            assert_eq!(
                read_record_with(&db, &PRODUCTION)
                    .unwrap()
                    .unwrap()
                    .commitment,
                moved.to,
                "started once: still moved"
            );
        }
    }
}

// ── the handshake digest of #350 B2, and the move ───────────────────────────

/// The handshake digest that public PR #384 (B2) declares at connect, computed
/// as that source defines it (see `consensus_config_schema4.rs`):
/// `BLAKE3("sumchain/protocol-digest/v2" ‖ protocol_digest ‖ build(genesis).commitment())`.
fn b2_handshake_digest(g: &Genesis, policy: &SchemaPolicy) -> ([u8; 91], Hash) {
    let pd = sumchain_state::protocol_digest::protocol_digest(g).unwrap();
    let running = ccfg::build_with(g, policy).unwrap();
    let mut preimage = [0u8; 91];
    preimage[..27].copy_from_slice(b"sumchain/protocol-digest/v2");
    preimage[27..59].copy_from_slice(pd.as_bytes());
    preimage[59..].copy_from_slice(running.commitment().as_bytes());
    (preimage, Hash::hash(&preimage))
}

/// Writing schema 5 changes no gate name, so neither the activation digest
/// nor the protocol digest moves; the move changes the RECORDED commitment
/// only. What B2 would declare follows the binary's written schema: a
/// schema-5 writer declares a different value from the schema-4 release for
/// the same genesis, whatever either node has recorded.
#[test]
fn the_move_changes_the_recorded_commitment_but_not_the_digests() {
    let g = g_ph();
    let (_d, db) = production_shaped_4_database();
    set_head(&db, HEAD);
    let activation = g.activation_digest().unwrap();
    let protocol = sumchain_state::protocol_digest::protocol_digest(&g).unwrap();
    let (_, handshake_5) = b2_handshake_digest(&g, &PRODUCTION);
    let recorded_before = ccfg::read_record(&db).unwrap().unwrap().commitment;
    let moved = move_to_schema_5(&db, HEAD);
    assert_ne!(
        recorded_before, moved.to,
        "the move changes the RECORDED commitment"
    );
    assert_eq!(g.activation_digest().unwrap(), activation);
    assert_eq!(
        sumchain_state::protocol_digest::protocol_digest(&g).unwrap(),
        protocol
    );
    assert_eq!(b2_handshake_digest(&g, &PRODUCTION).1, handshake_5);

    let (preimage_4, handshake_4) = b2_handshake_digest(&g, &SCHEMA_4_RELEASE);
    let (preimage_5, _) = b2_handshake_digest(&g, &PRODUCTION);
    assert_eq!(
        preimage_4[..59],
        preimage_5[..59],
        "domain and protocol digest"
    );
    assert_ne!(handshake_4, handshake_5, "the running commitment differs");
    let four = ccfg::build_with(&g, &SCHEMA_4_RELEASE).unwrap();
    assert_eq!(four.extend_to(&SCHEMA_5).unwrap(), ccfg::build(&g).unwrap());
}

/// The schema-5 encoding of B2's golden genesis (`ChainParams::default()`,
/// every gate unset) is the schema-4 encoding with schema number 5, field
/// count + 3, the two gates' absent entries (14 bytes) right after `0x1047`'s,
/// and the tag's absent entry (7 bytes) right after `0x252a`'s.
#[test]
fn the_schema_5_encoding_is_the_schema_4_encoding_plus_three_absent_entries() {
    let v = KeyPair::from_bytes([31u8; 32]);
    let g = Genesis::new(
        1,
        1_734_624_000_000,
        vec![v.public_key().to_base58()],
        std::collections::HashMap::from([(v.address().to_base58(), 1_000_000u128)]),
        ChainParams::default(),
    );
    let b4 = ccfg::build_with(&g, &SCHEMA_4_RELEASE).unwrap().encode();
    let five = ccfg::build(&g).unwrap();
    let b5 = five.encode();
    assert_eq!(b5.len(), b4.len() + 21);
    assert_eq!(&b5[..7], &b4[..7]);
    assert_eq!(u16::from_le_bytes([b5[7], b5[8]]), 5);
    assert_eq!(
        u16::from_le_bytes([b5[9], b5[10]]),
        u16::from_le_bytes([b4[9], b4[10]]) + 3
    );
    let after = |id: u16| {
        let [lo, hi] = id.to_le_bytes();
        b4.windows(7)
            .position(|w| w == [lo, hi, 0, 0, 0, 0, 0])
            .unwrap_or_else(|| panic!("{id:#06x} absent entry"))
            + 7
    };
    let at_gates = after(0x1047);
    let at_tag = after(0x252a);
    assert!(at_gates < at_tag);
    assert_eq!(&b5[11..at_gates], &b4[11..at_gates]);
    assert_eq!(
        &b5[at_gates..at_gates + 14],
        &[0x48, 0x10, 0, 0, 0, 0, 0, 0x49, 0x10, 0, 0, 0, 0, 0]
    );
    assert_eq!(&b5[at_gates + 14..at_tag + 14], &b4[at_gates..at_tag]);
    assert_eq!(&b5[at_tag + 14..at_tag + 21], &[0x2b, 0x25, 0, 0, 0, 0, 0]);
    assert_eq!(&b5[at_tag + 21..], &b4[at_tag..]);
    eprintln!(
        "B2-GOLDEN\tprotocol_digest={}\trunning_commitment_schema5={}\thandshake_digest={}",
        sumchain_state::protocol_digest::protocol_digest(&g).unwrap(),
        five.commitment(),
        b2_handshake_digest(&g, &PRODUCTION).1
    );
}
