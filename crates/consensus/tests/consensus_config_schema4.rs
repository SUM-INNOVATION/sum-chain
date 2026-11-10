//! ConsensusConfig schema 4 (#268): schema 3 plus exactly four optional U64
//! gates (0x1044 to 0x1047), which this binary writes.
//!
//! Every upgrade test starts from `tests/data/consensus_config_schema1_db.tsv`:
//! the exact `cf::META` entries the schema-1 release writes (a baseline, a
//! gate reschedule and an operator acknowledgement), loaded into a fresh
//! database byte for byte. A schema-2 database is that one moved by the
//! release that wrote schema 2; a schema-3 database is that one moved by the
//! releases that wrote schema 3 ([`SCHEMA_3_RELEASE`], the deployed release's
//! policy); and the production-shaped database is the schema-1 one moved to
//! schema 3 in one step and then given the peer-declaration deadline and the
//! node-registry gate as one future-gate reschedule, which is the history
//! production records (`schema-transition`, `gate-reschedule`).
//!
//! What an operator relies on, in order:
//!
//! * installing this binary changes nothing: a schema-1, schema-2 or schema-3
//!   record runs as it stands, compared in its own schema, never re-encoded at
//!   start, and nothing is written;
//! * none of the four gates can be set until the record is schema 4: before
//!   the move, a genesis that sets one refuses start and names the exact
//!   stopped-node command, both commitments included;
//! * the move is one step from schema 1, 2 or 3, re-encodes the recorded
//!   rules, changes none, keeps the older encoding in the history, and writes
//!   exactly two keys — the record and one transition — in one batch;
//! * the move refuses, and writes nothing, on a wrong commitment, a record
//!   already in schema 4, a damaged record and a record of a schema this
//!   binary does not implement;
//! * the move consults no genesis: a record that disagrees with the genesis
//!   refuses start before the move and after it, naming the same fields;
//! * after the move, scheduling a gate at a future height is an ordinary
//!   future-gate reschedule; a height already reached is refused;
//! * the releases that wrote schema 3 refuse a schema-4 record and rewrite
//!   nothing.

use std::collections::BTreeMap;

use sumchain_consensus::consensus_config::{
    self as ccfg,
    codec::commitment_of,
    record::{
        acknowledge_schema_transition_with, acknowledge_with, check_at_startup_with,
        pending_schema_transition_with, read_record_with, read_transitions_with, RECORD_KEY,
        TRANSITION_PREFIX,
    },
    schema::{SCHEMA_2_ADDED, SCHEMA_3_ADDED, SCHEMA_4_ADDED},
    ConfigError, ConsensusConfig, SchemaPolicy, Source, StartupOutcome, TransitionKind, Value,
    PRODUCTION, SCHEMA_1, SCHEMA_2, SCHEMA_3, SCHEMA_4, SCHEMA_5,
};
use sumchain_crypto::KeyPair;
use sumchain_genesis::{ChainParams, Genesis};
use sumchain_primitives::Hash;
use sumchain_storage::{cf, db::ALL_CFS, Database};
use tempfile::TempDir;

/// The four gates schema 4 adds, in id order, with a setter for each.
type SetGate = fn(&mut ChainParams, Option<u64>);
const GATES: [(u16, &str, SetGate); 4] = [
    (
        0x1044,
        "archive_unbonding_own_challenges_enabled_from_height",
        |p, h| p.archive_unbonding_own_challenges_enabled_from_height = h,
    ),
    (
        0x1045,
        "por_attested_targets_enabled_from_height",
        |p, h| p.por_attested_targets_enabled_from_height = h,
    ),
    (
        0x1046,
        "strict_transaction_signatures_enabled_from_height",
        |p, h| p.strict_transaction_signatures_enabled_from_height = h,
    ),
    (
        0x1047,
        "staking_submit_evidence_unsupported_enabled_from_height",
        |p, h| p.staking_submit_evidence_unsupported_enabled_from_height = h,
    ),
];
const GATE_IDS: [u16; 4] = [0x1044, 0x1045, 0x1046, 0x1047];
/// `peer_protocol_declaration_required_from_height`, a schema-1 gate.
const PEER: u16 = 0x1029;
/// `node_registry_update_status_unsupported_enabled_from_height`, schema 3's.
const NODE_REGISTRY: u16 = 0x1043;

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

/// The releases that wrote schema 3: they
/// read schemas 1, 2 and 3, write 3, and know schema 4 only as a draft whose
/// fields must stay absent. (Every stand-in here knows the draft schema 5 too:
/// this test binary's genesis declares its gates, unset.)
static SCHEMA_3_RELEASE: SchemaPolicy = SchemaPolicy {
    reads: &[&SCHEMA_1, &SCHEMA_2, &SCHEMA_3],
    writes: &SCHEMA_3,
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

/// A schema-3 node's record genesis: [`g2`] with the
/// peer-declaration deadline and the node-registry gate scheduled.
fn g_ph() -> Genesis {
    let mut g = g2();
    g.params.peer_protocol_declaration_required_from_height = Some(P);
    g.params
        .node_registry_update_status_unsupported_enabled_from_height = Some(H_GATE);
    g
}

/// The heights [`g_ph`] schedules, below [`HEIGHT`]: both have passed.
const P: u64 = 30;
const H_GATE: u64 = 40;

/// [`g_ph`] with schema-4 gate `i` at `at`.
fn with_gate(i: usize, at: u64) -> Genesis {
    let mut g = g_ph();
    (GATES[i].2)(&mut g.params, Some(at));
    g
}

/// Height of the fixture's last write.
const HEIGHT: u64 = 20;
/// Height of the production-shaped database's head: P and H have passed.
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

/// The schema-1 fixture moved by `policy`, a release that writes its schema.
fn moved_by(policy: &SchemaPolicy) -> (TempDir, Database) {
    let (dir, db) = schema_1_database();
    let p = pending_schema_transition_with(&db, policy)
        .unwrap()
        .unwrap();
    acknowledge_schema_transition_with(&db, HEIGHT, p.old, p.new, policy).unwrap();
    assert_eq!(
        read_record_with(&db, policy)
            .unwrap()
            .unwrap()
            .config
            .schema()
            .number,
        policy.writes.number
    );
    (dir, db)
}

fn schema_2_database() -> (TempDir, Database) {
    moved_by(&SCHEMA_2_RELEASE)
}

fn schema_3_database() -> (TempDir, Database) {
    moved_by(&SCHEMA_3_RELEASE)
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
    let kinds: Vec<TransitionKind> = read_transitions_with(&db, &SCHEMA_3_RELEASE)
        .unwrap()
        .iter()
        .map(|t| t.kind)
        .collect();
    assert_eq!(
        &kinds[kinds.len() - 2..],
        [
            TransitionKind::SchemaTransition,
            TransitionKind::GateReschedule
        ]
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

/// This binary's one-step move of `db` to schema 4, with the commitments it
/// offers.
fn move_to_schema_4(db: &Database, height: u64) -> ccfg::SchemaTransitioned {
    let p = ccfg::pending_schema_transition(db).unwrap().unwrap();
    assert_eq!(p.to_schema, 4);
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

// ── schema 4 ────────────────────────────────────────────────────────────────

#[test]
fn schema_4_is_schema_3_plus_the_four_gates_and_this_binary_writes_it() {
    assert_eq!(SCHEMA_4.number, 4);
    assert!(std::ptr::eq(SCHEMA_4.previous.unwrap(), &SCHEMA_3));
    let added: Vec<(u16, &str)> = SCHEMA_4_ADDED
        .iter()
        .map(|a| (a.spec.id, a.spec.name))
        .collect();
    assert_eq!(
        added,
        GATES.iter().map(|(id, n, _)| (*id, *n)).collect::<Vec<_>>()
    );
    for a in SCHEMA_4_ADDED {
        assert!(matches!(a.source, Source::Gate), "{}", a.spec.name);
        assert!(a.spec.optional, "{}", a.spec.name);
        assert_eq!(ccfg::fields::gate_id(a.spec.name), Some(a.spec.id));
    }
    assert_eq!(SCHEMA_4.specs().len(), SCHEMA_3.specs().len() + 4);
    assert_eq!(
        SCHEMA_4.added_since(&SCHEMA_1).len(),
        SCHEMA_2_ADDED.len() + SCHEMA_3_ADDED.len() + 4
    );

    assert!(std::ptr::eq(PRODUCTION.writes, &SCHEMA_4));
    // It knows the draft schema 5, which extends schema 4.
    assert!(std::ptr::eq(PRODUCTION.knows, &SCHEMA_5));
    assert!(std::ptr::eq(SCHEMA_5.previous.unwrap(), &SCHEMA_4));
    assert_eq!(
        PRODUCTION
            .reads
            .iter()
            .map(|s| s.number)
            .collect::<Vec<_>>(),
        [1, 2, 3, 4],
        "older schemas are read for good"
    );
    for p in [
        &PRODUCTION,
        &SCHEMA_1_RELEASE,
        &SCHEMA_2_RELEASE,
        &SCHEMA_3_RELEASE,
    ] {
        p.check().unwrap();
    }

    // Unset in every default: declaring the fields schedules nothing.
    for params in [
        ChainParams::default(),
        ChainParams::with_contracts_enabled(),
    ] {
        assert_eq!(
            params.archive_unbonding_own_challenges_enabled_from_height,
            None
        );
        assert_eq!(params.por_attested_targets_enabled_from_height, None);
        assert_eq!(
            params.strict_transaction_signatures_enabled_from_height,
            None
        );
        assert_eq!(
            params.staking_submit_evidence_unsupported_enabled_from_height,
            None
        );
    }
    let c = ccfg::build(&g2()).unwrap();
    for id in GATE_IDS {
        assert_eq!(c.get(id), Some(&Value::Absent), "{id:#06x}");
    }
}

/// No tracked genesis file or template sets any of the four gates: each is
/// absent from the file or `null`.
#[test]
fn no_tracked_genesis_or_template_sets_a_schema_4_gate() {
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
        for (_, name, _) in GATES {
            let set = v
                .get("params")
                .and_then(|p| p.get(name))
                .is_some_and(|x| !x.is_null());
            assert!(!set, "{}: {name} is set", f.display());
        }
    }
}

#[test]
fn a_fresh_database_records_schema_4_directly() {
    let dir = TempDir::new().unwrap();
    let db = Database::open_default(dir.path()).unwrap();
    let expected = ccfg::build(&g2()).unwrap();
    assert_eq!(expected.schema().number, 4);
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
    // And it is the schema-3 configuration plus the four gates, absent.
    assert_eq!(
        ccfg::build_with(&g2(), &SCHEMA_3_RELEASE)
            .unwrap()
            .extend_to(&SCHEMA_4)
            .unwrap(),
        expected
    );
}

// ── installing the binary changes nothing ───────────────────────────────────

/// A schema-1, schema-2, schema-3 or production-shaped database runs as it
/// stands, however often this binary starts, nothing is written, and the move
/// straight to schema 4 is offered.
#[test]
fn older_databases_run_as_they_stand_and_are_offered_schema_4_in_one_step() {
    for (label, from, g, (_d, db)) in [
        ("schema 1", 1, g2(), schema_1_database()),
        ("schema 2", 2, g2(), schema_2_database()),
        ("schema 3", 3, g2(), schema_3_database()),
        ("production-shaped", 3, g_ph(), production_shaped_database()),
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
        assert_eq!((p.from_schema, p.to_schema), (from, 4), "{label}");
        assert_eq!(p.old, r.commitment, "{label}");
        assert_eq!(
            p.new,
            r.config.extend_to(&SCHEMA_4).unwrap().commitment(),
            "{label}"
        );
    }
}

// ── the move ────────────────────────────────────────────────────────────────

/// One step from schema 1, 2 or 3: every field the newer schemas add is
/// recorded absent, the history keeps every earlier entry and gains one schema
/// transition listing exactly the added fields, the moved record runs
/// unchanged, and all three land on the same commitment: the same rules.
#[test]
fn the_one_step_move_keeps_the_rules_and_the_history() {
    let mut landed = Vec::new();
    for (label, from, (_d, db)) in [
        ("schema 1", &SCHEMA_1, schema_1_database()),
        ("schema 2", &SCHEMA_2, schema_2_database()),
        ("schema 3", &SCHEMA_3, schema_3_database()),
    ] {
        let old_history = ccfg::read_transitions(&db).unwrap();
        let old = ccfg::read_record(&db).unwrap().unwrap();
        let done = move_to_schema_4(&db, HEIGHT);
        assert_eq!((done.from_schema, done.to_schema), (from.number, 4));
        assert_eq!(done.from, old.commitment);
        let expected_added: Vec<u16> = SCHEMA_4.added_since(from).iter().map(|s| s.id).collect();
        assert_eq!(done.added, expected_added, "{label}");

        let r = ccfg::read_record(&db).unwrap().unwrap();
        assert_eq!(r.config.schema().number, 4);
        assert_eq!(r.commitment, done.to);
        assert_eq!(r.config, old.config.extend_to(&SCHEMA_4).unwrap());
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

/// The production-shaped record moves by exactly the four gates; its history
/// becomes `…, schema-transition, gate-reschedule, schema-transition`; the
/// scheduled peer deadline and node-registry gate are kept; and the same
/// genesis starts unchanged.
#[test]
fn the_production_shaped_record_moves_by_exactly_the_four_gates() {
    let (_d, db) = production_shaped_database();
    let old = ccfg::read_record(&db).unwrap().unwrap();
    let done = move_to_schema_4(&db, HEAD);
    assert_eq!((done.from_schema, done.to_schema), (3, 4));
    assert_eq!(done.added, GATE_IDS);
    let r = ccfg::read_record(&db).unwrap().unwrap();
    assert_eq!(r.config.get(PEER), Some(&Value::U64(P)));
    assert_eq!(r.config.get(NODE_REGISTRY), Some(&Value::U64(H_GATE)));
    assert_eq!(r.config, old.config.extend_to(&SCHEMA_4).unwrap());
    let kinds: Vec<&str> = ccfg::read_transitions(&db)
        .unwrap()
        .iter()
        .map(|t| t.kind.label())
        .collect();
    assert_eq!(
        &kinds[kinds.len() - 3..],
        ["schema-transition", "gate-reschedule", "schema-transition"]
    );
    assert_eq!(
        ccfg::check_at_startup(&db, &g_ph(), HEAD).unwrap(),
        StartupOutcome::Unchanged {
            commitment: done.to
        }
    );
    // The rules did not change: the moved record is the schema-4 configuration
    // this binary computes from the same genesis.
    assert_eq!(r.config, ccfg::build(&g_ph()).unwrap());
}

/// The move writes exactly two rows — the record, replaced, and one new
/// transition — and touches no other row of any column family.
#[test]
fn the_move_writes_only_the_record_and_one_transition() {
    let (_d, db) = production_shaped_database();
    let before = all_rows(&db);
    let r = ccfg::read_record(&db).unwrap().unwrap();
    move_to_schema_4(&db, HEAD);
    let after = all_rows(&db);
    let changed: Vec<&(String, Vec<u8>)> = after
        .keys()
        .chain(before.keys())
        .filter(|k| before.get(*k) != after.get(*k))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let next = transition_key(r.transition_count + 1);
    assert_eq!(
        changed,
        vec![
            &(cf::META.to_string(), RECORD_KEY.to_vec()),
            &(cf::META.to_string(), next.clone()),
        ]
    );
    assert!(!before.contains_key(&(cf::META.to_string(), next)));
}

/// Moving is idempotent: once moved there is nothing left to move, a second
/// run refuses with any commitments, and nothing is written.
#[test]
fn a_moved_record_has_nothing_left_to_move_and_a_rerun_writes_nothing() {
    let (_d, db) = production_shaped_database();
    let done = move_to_schema_4(&db, HEAD);
    let before = all_rows(&db);
    assert_eq!(ccfg::pending_schema_transition(&db).unwrap(), None);
    for (old, new) in [(done.to, done.to), (done.from, done.to)] {
        let err = ccfg::acknowledge_schema_transition(&db, HEAD, old, new).unwrap_err();
        assert!(
            err.to_string().contains("already recorded in schema 4"),
            "{err}"
        );
    }
    assert_eq!(all_rows(&db), before);
}

/// The move names both commitments exactly; anything else refuses and writes
/// nothing. The refusal of a wrong `--new` names the right one.
#[test]
fn the_move_must_name_both_commitments_exactly() {
    let (_d, db) = production_shaped_database();
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
            "trailing byte",
            Box::new(|db| tamper(db, RECORD_KEY, |r| r.push(0))),
        ),
        (
            "unknown record version",
            Box::new(|db| tamper(db, RECORD_KEY, |r| r[0] = 9)),
        ),
        (
            "a transition missing",
            Box::new(|db| db.delete(cf::META, &transition_key(1)).unwrap()),
        ),
        (
            "a transition the record does not count",
            Box::new(|db| {
                let n = ccfg::read_record(db).unwrap().unwrap().transition_count;
                let last = db.get(cf::META, &transition_key(n)).unwrap().unwrap();
                db.put(cf::META, &transition_key(n + 1), &last).unwrap();
            }),
        ),
        (
            "a kept encoding that does not match its commitment",
            Box::new(|db| tamper(db, &transition_key(1), |t| *t.last_mut().unwrap() ^= 1)),
        ),
    ];
    for (what, damage) in cases {
        let (_d, db) = production_shaped_database();
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

/// A record whose encoding declares schema 5 — a binary this one predates —
/// is refused as written by a newer binary, by the move and by start, and
/// nothing is written.
#[test]
fn a_record_of_an_unknown_future_schema_is_refused_and_nothing_is_written() {
    let dir = TempDir::new().unwrap();
    let db = Database::open_default(dir.path()).unwrap();
    ccfg::check_at_startup(&db, &g2(), 0).unwrap();
    // Re-label the fresh schema-4 record as schema 5, with a commitment that
    // matches its bytes: a well-formed record of a schema this binary lacks.
    tamper(&db, RECORD_KEY, |r| {
        r[87 + 7..87 + 9].copy_from_slice(&5u16.to_le_bytes());
        let c = commitment_of(&r[87..]);
        r[11..43].copy_from_slice(c.as_bytes());
        r[51..83].copy_from_slice(c.as_bytes());
    });
    let raw = db.get(cf::META, RECORD_KEY).unwrap().unwrap();
    assert_eq!(
        ConsensusConfig::decode(&raw[87..]),
        Err(ConfigError::UnknownSchema(5))
    );
    let before = all_rows(&db);
    let err = ccfg::read_record(&db).unwrap_err();
    assert!(matches!(err, ConfigError::RecordCorrupt(_)), "{err}");
    assert!(err.to_string().contains("schema 5"), "{err}");
    assert!(err.to_string().contains("newer binary"), "{err}");
    let c = commitment_of(&raw[87..]);
    let err = ccfg::acknowledge_schema_transition(&db, 0, c, c).unwrap_err();
    assert!(err.to_string().contains("newer binary"), "{err}");
    assert!(ccfg::pending_schema_transition(&db).is_err());
    assert!(ccfg::check_at_startup(&db, &g2(), 0).is_err());
    assert_eq!(all_rows(&db), before, "nothing written");
}

/// The move consults no genesis. A record that disagrees with the node's
/// genesis in a rule refuses start before the move, naming the field and the
/// field-level acknowledgement; the move still re-encodes the record exactly;
/// and after it start refuses the same way, naming the same field. Nothing
/// else is written.
#[test]
fn a_record_that_disagrees_with_the_genesis_is_refused_before_and_after_the_move() {
    let (_d, db) = production_shaped_database();
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
                3 => &SCHEMA_3_RELEASE,
                _ => &PRODUCTION,
            },
        )
        .unwrap();
        ids(&r.config.diff(&computed).unwrap())
    };
    assert_eq!(refused(&db), vec![field], "before the move");
    let done = move_to_schema_4(&db, HEAD);
    assert_eq!(ccfg::read_record(&db).unwrap().unwrap().commitment, done.to);
    assert_eq!(refused(&db), vec![field], "after the move: the same field");
}

// ── ordering: the gates wait for the move ───────────────────────────────────

/// Before the move, a genesis that sets any one of the four gates — with the
/// peer deadline at or below it, as genesis validation requires — refuses
/// start and names the stopped-node command with both commitments; the
/// field-level acknowledgement refuses too. Nothing is written, on schema-1,
/// schema-2, schema-3 and production-shaped databases alike. Unset again, the
/// node starts unchanged.
#[test]
fn before_the_move_setting_a_schema_4_gate_refuses_and_names_the_command() {
    for (label, base, (_d, db)) in [
        ("schema 1", g2(), schema_1_database()),
        ("schema 2", g2(), schema_2_database()),
        ("schema 3", g2(), schema_3_database()),
        ("production-shaped", g_ph(), production_shaped_database()),
    ] {
        let before = all_rows(&db);
        let r = ccfg::read_record(&db).unwrap().unwrap();
        let p = ccfg::pending_schema_transition(&db).unwrap().unwrap();
        for (i, (_, name, set_gate)) in GATES.into_iter().enumerate() {
            let mut g = base.clone();
            g.params.peer_protocol_declaration_required_from_height = base
                .params
                .peer_protocol_declaration_required_from_height
                .or(Some(HEAD + 100));
            set_gate(&mut g.params, Some(HEAD + 200 + i as u64));
            g.validate().unwrap();

            let err = ccfg::check_at_startup(&db, &g, HEAD).unwrap_err();
            let text = err.to_string();
            assert!(matches!(err, ConfigError::Refused(_)), "{label}: {text}");
            assert!(text.contains(name), "{label}: {text}");
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
            assert_eq!(all_rows(&db), before, "{label}, {name}: nothing written");
        }
        assert_eq!(
            ccfg::check_at_startup(&db, &base, HEAD).unwrap(),
            StartupOutcome::Unchanged {
                commitment: r.commitment
            },
            "{label}"
        );
    }
}

/// After the move, each gate at a future height is an ordinary future-gate
/// reschedule of exactly that field, recorded in the history; a height the
/// chain has already reached is refused and nothing is written.
#[test]
fn after_the_move_a_schema_4_gate_is_a_future_gate_reschedule() {
    for (i, (id, name, _)) in GATES.into_iter().enumerate() {
        let (_d, db) = production_shaped_database();
        let moved = move_to_schema_4(&db, HEAD);

        let before = all_rows(&db);
        for at in [HEAD - 1, HEAD] {
            let err = ccfg::check_at_startup(&db, &with_gate(i, at), HEAD).unwrap_err();
            assert!(
                err.to_string().contains("already passed"),
                "{name} {at}: {err}"
            );
            assert!(err.to_string().contains(name), "{name} {at}: {err}");
        }
        assert_eq!(all_rows(&db), before, "{name}: nothing written");

        let g = with_gate(i, HEAD + 100);
        g.validate().unwrap();
        let out = ccfg::check_at_startup(&db, &g, HEAD).unwrap();
        let StartupOutcome::GatesRescheduled { from, to, changes } = out else {
            panic!("{name}: expected a reschedule, got {out:?}");
        };
        assert_eq!(from, moved.to);
        assert_eq!(to, ccfg::build(&g).unwrap().commitment());
        assert_eq!(ids(&changes), vec![id], "{name}");
        let last = ccfg::read_transitions(&db).unwrap().pop().unwrap();
        assert_eq!(last.kind, TransitionKind::GateReschedule);
        assert_eq!(last.changed_ids, vec![id]);
        assert_eq!(
            ccfg::check_at_startup(&db, &g, HEAD + 1).unwrap(),
            StartupOutcome::Unchanged { commitment: to }
        );
        // Still ahead of the chain: it can be unset again.
        assert!(matches!(
            ccfg::check_at_startup(&db, &g_ph(), HEAD + 2).unwrap(),
            StartupOutcome::GatesRescheduled { .. }
        ));
    }
}

// ── older binaries ──────────────────────────────────────────────────────────

/// The releases that wrote schema 3 — the deployed one among them — and the
/// older ones refuse a schema-4 record, moved or fresh, as written by a newer
/// binary, and rewrite nothing. This binary runs it.
#[test]
fn older_releases_refuse_a_schema_4_record_and_rewrite_nothing() {
    let (_d1, moved_from_1) = schema_1_database();
    move_to_schema_4(&moved_from_1, HEIGHT);
    let (_d3, moved_from_ph) = production_shaped_database();
    move_to_schema_4(&moved_from_ph, HEAD);
    let fresh_dir = TempDir::new().unwrap();
    let fresh = Database::open_default(fresh_dir.path()).unwrap();
    ccfg::check_at_startup(&fresh, &g2(), 0).unwrap();

    for (label, db, g) in [
        ("moved from schema 1", &moved_from_1, g2()),
        ("moved from production shape", &moved_from_ph, g_ph()),
        ("fresh", &fresh, g2()),
    ] {
        let before = all_rows(db);
        let raw = db.get(cf::META, RECORD_KEY).unwrap().unwrap();
        for (who, policy) in [
            ("schema-1 release", &SCHEMA_1_RELEASE),
            ("schema-2 release", &SCHEMA_2_RELEASE),
            ("schema-3 release", &SCHEMA_3_RELEASE),
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
                Err(ConfigError::UnknownSchema(4)),
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
/// lost, as a crash before the commit loses it, leaves the old database row
/// for row, from which the move can be run again.
#[test]
fn a_move_lost_before_the_commit_leaves_the_old_record_and_can_be_retried() {
    let (dir, db) = production_shaped_database();
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
        check_at_startup_with(&db, &g_ph(), HEAD, &SCHEMA_3_RELEASE).unwrap(),
        StartupOutcome::Unchanged { commitment: p.old }
    );
    let done = ccfg::acknowledge_schema_transition(&db, HEAD, p.old, p.new).unwrap();
    assert_eq!(done.to, p.new);
}

/// A database holding only half of a move — which one batch rules out, and
/// only damage can produce — is refused by every reader, never repaired or
/// recreated.
#[test]
fn half_a_move_is_refused_and_never_repaired() {
    let (_dm, moved) = production_shaped_database();
    let r = ccfg::read_record(&moved).unwrap().unwrap();
    let seq = r.transition_count + 1;
    move_to_schema_4(&moved, HEAD);
    let new_record = moved.get(cf::META, RECORD_KEY).unwrap().unwrap();
    let new_transition = moved.get(cf::META, &transition_key(seq)).unwrap().unwrap();

    for (what, only_record) in [("the transition alone", false), ("the record alone", true)] {
        let (_d, db) = production_shaped_database();
        if only_record {
            db.put(cf::META, RECORD_KEY, &new_record).unwrap();
        } else {
            db.put(cf::META, &transition_key(seq), &new_transition)
                .unwrap();
        }
        let before = all_rows(&db);
        for policy in [&PRODUCTION, &SCHEMA_3_RELEASE] {
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
        n => panic!("no release writes schema {n}"),
    }
}

/// Before the node first starts on the moved record, the move reverts to the
/// exact rows it replaced — every column family, byte for byte — from schema
/// 1, 2, 3 and the production shape. The release the node came from then reads
/// and starts on it unchanged, and this binary offers the same move again.
#[test]
fn before_the_first_start_the_move_reverts_to_exactly_the_old_rows() {
    for (label, from, g, (_d, db)) in [
        ("schema 1", 1, g2(), schema_1_database()),
        ("schema 2", 2, g2(), schema_2_database()),
        ("schema 3", 3, g2(), schema_3_database()),
        ("production-shaped", 3, g_ph(), production_shaped_database()),
    ] {
        set_head(&db, HEAD);
        let before = all_rows(&db);
        let r = ccfg::read_record(&db).unwrap().unwrap();
        let offered = ccfg::pending_schema_transition(&db).unwrap().unwrap();
        let moved = move_to_schema_4(&db, HEAD);

        let p = ccfg::pending_schema_revert(&db).unwrap();
        assert_eq!(p.seq, r.transition_count + 1, "{label}");
        assert_eq!(p.at_height, HEAD, "{label}");
        assert_eq!((p.from_schema, p.to_schema), (4, from), "{label}");
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
            (p.seq, 4, from, moved.to, r.commitment),
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
    let (_d, db) = production_shaped_database();
    set_head(&db, HEAD);
    move_to_schema_4(&db, HEAD);
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

/// Once the chain has moved off the height the move was made at — a block
/// above it, the head above it, or the head below it — the revert is refused
/// and nothing is written. Recovery is then forward only.
#[test]
fn the_revert_is_refused_once_the_chain_has_moved_past_the_move() {
    type Advance = fn(&Database);
    let cases: [(&str, Advance); 4] = [
        ("one block above, as imported", |db| {
            index_block_at(db, HEAD + 1);
            set_head(db, HEAD + 1);
        }),
        ("many blocks above", |db| {
            for h in HEAD + 1..=HEAD + 10 {
                index_block_at(db, h);
            }
            set_head(db, HEAD + 10);
        }),
        ("an indexed block above an unmoved head", |db| {
            index_block_at(db, HEAD + 3)
        }),
        ("the head below the move", |db| set_head(db, HEAD - 1)),
    ];
    for (what, advance) in cases {
        let (_d, db) = production_shaped_database();
        set_head(&db, HEAD);
        index_block_at(&db, HEAD);
        move_to_schema_4(&db, HEAD);
        let p = ccfg::pending_schema_revert(&db).unwrap();
        advance(&db);
        let before = all_rows(&db);
        let err = ccfg::pending_schema_revert(&db).unwrap_err();
        assert!(matches!(err, ConfigError::Refused(_)), "{what}: {err}");
        let err = ccfg::revert_schema_transition(&db, p.old, p.new).unwrap_err();
        assert!(matches!(err, ConfigError::Refused(_)), "{what}: {err}");
        let text = err.to_string();
        if what != "the head below the move" {
            assert!(text.contains("forward only"), "{what}: {text}");
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
/// this binary's schema transition — a later gate reschedule, an older
/// release's own move, an operator acknowledgement, or no transition at all —
/// refuses, and nothing is written.
#[test]
fn the_revert_is_refused_without_an_unstarted_move() {
    // A start that recorded a reschedule after the move.
    let (_d1, rescheduled) = production_shaped_database();
    move_to_schema_4(&rescheduled, HEAD);
    ccfg::check_at_startup(&rescheduled, &with_gate(0, HEAD + 100), HEAD).unwrap();
    // The schema-3 release's own move (last transition: a schema transition
    // into schema 3).
    let (_d2, schema_3) = schema_3_database();
    set_head(&schema_3, HEIGHT);
    // The schema-1 release's history (last: an operator acknowledgement).
    let (_d3, schema_1) = schema_1_database();
    // A fresh schema-4 record (no transition).
    let fresh_dir = TempDir::new().unwrap();
    let fresh = Database::open_default(fresh_dir.path()).unwrap();
    ccfg::check_at_startup(&fresh, &g2(), 0).unwrap();
    let empty_dir = TempDir::new().unwrap();
    let empty = Database::open_default(empty_dir.path()).unwrap();

    for (what, db, says) in [
        ("a later reschedule", &rescheduled, "gate-reschedule"),
        (
            "the schema-3 release's move",
            &schema_3,
            "this binary writes schema 4",
        ),
        ("an acknowledgement", &schema_1, "operator-acknowledged"),
        ("a fresh record", &fresh, "no transition"),
        ("no record", &empty, "no consensus configuration baseline"),
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

/// A second revert has nothing to undo; a damaged record, or one of a schema
/// this binary does not read, is refused as damaged. Nothing is written.
#[test]
fn the_revert_refuses_a_second_run_and_a_damaged_or_unknown_record() {
    let (_d, db) = production_shaped_database();
    set_head(&db, HEAD);
    move_to_schema_4(&db, HEAD);
    let p = ccfg::pending_schema_revert(&db).unwrap();
    ccfg::revert_schema_transition(&db, p.old, p.new).unwrap();
    let before = all_rows(&db);
    let err = ccfg::revert_schema_transition(&db, p.old, p.new).unwrap_err();
    assert!(matches!(err, ConfigError::Refused(_)), "{err}");
    assert_eq!(all_rows(&db), before, "a second run writes nothing");

    let (_d2, db) = production_shaped_database();
    set_head(&db, HEAD);
    move_to_schema_4(&db, HEAD);
    let p = ccfg::pending_schema_revert(&db).unwrap();
    tamper(&db, RECORD_KEY, |r| *r.last_mut().unwrap() ^= 1);
    let before = all_rows(&db);
    let err = ccfg::revert_schema_transition(&db, p.old, p.new).unwrap_err();
    assert!(matches!(err, ConfigError::RecordCorrupt(_)), "{err}");
    assert_eq!(all_rows(&db), before, "damaged: nothing written");

    let dir = TempDir::new().unwrap();
    let db = Database::open_default(dir.path()).unwrap();
    ccfg::check_at_startup(&db, &g2(), 0).unwrap();
    tamper(&db, RECORD_KEY, |r| {
        r[87 + 7..87 + 9].copy_from_slice(&5u16.to_le_bytes());
        let c = commitment_of(&r[87..]);
        r[11..43].copy_from_slice(c.as_bytes());
        r[51..83].copy_from_slice(c.as_bytes());
    });
    let before = all_rows(&db);
    let err = ccfg::pending_schema_revert(&db).unwrap_err();
    assert!(err.to_string().contains("newer binary"), "{err}");
    assert_eq!(all_rows(&db), before, "schema 5: nothing written");
}

/// The restored record and the removal of the move's transition are one
/// durable batch. A batch staged and lost leaves the moved database row for
/// row, and the revert can be run again; half a revert — which one batch rules
/// out — is refused by this binary and by the schema-3 release, never
/// repaired.
#[test]
fn a_lost_revert_leaves_the_moved_record_and_half_a_revert_is_refused() {
    let (dir, db) = production_shaped_database();
    set_head(&db, HEAD);
    let unmoved = all_rows(&db);
    let original = db.get(cf::META, RECORD_KEY).unwrap().unwrap();
    move_to_schema_4(&db, HEAD);
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
        let (_d, db) = production_shaped_database();
        set_head(&db, HEAD);
        move_to_schema_4(&db, HEAD);
        if what == "the record restored alone" {
            db.put(cf::META, RECORD_KEY, &original).unwrap();
        } else {
            db.delete(cf::META, &transition_key(p.seq)).unwrap();
        }
        let before = all_rows(&db);
        for policy in [&PRODUCTION, &SCHEMA_3_RELEASE] {
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

// ── the start marker ────────────────────────────────────────────────────────

use sumchain_consensus::consensus_config::{
    read_start_marker, record_start, RecordState, StartMarker, START_MARKER_KEY,
};

fn marker_key() -> (String, Vec<u8>) {
    (cf::META.to_string(), START_MARKER_KEY.to_vec())
}

/// A normal start writes the marker as its one row: the attempt count, the
/// configuration record's state and the head as they are at that start. The
/// move writes no marker, and the revert neither writes nor deletes one.
#[test]
fn a_start_writes_exactly_the_marker_and_the_move_and_revert_leave_it_alone() {
    let dir = TempDir::new().unwrap();
    let db = Database::open_default(dir.path()).unwrap();
    assert_eq!(read_start_marker(&db).unwrap(), None);
    let before = all_rows(&db);
    let m = record_start(&db).unwrap();
    assert_eq!(
        m,
        StartMarker {
            attempt: 1,
            record: RecordState::Absent,
            head: None
        }
    );
    let after = all_rows(&db);
    let changed: Vec<_> = after
        .keys()
        .chain(before.keys())
        .filter(|k| before.get(*k) != after.get(*k))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    assert_eq!(changed, vec![&marker_key()], "exactly the marker row");
    assert_eq!(read_start_marker(&db).unwrap(), Some(m));

    // With a record and a head, both are recorded; the attempt counts.
    ccfg::check_at_startup(&db, &g2(), 0).unwrap();
    let r = ccfg::read_record(&db).unwrap().unwrap();
    set_head(&db, 7);
    sumchain_storage::schema::BlockStore::new(&db)
        .set_latest_hash(&h(C2))
        .unwrap();
    let m = record_start(&db).unwrap();
    assert_eq!(
        m,
        StartMarker {
            attempt: 2,
            record: RecordState::Present {
                transition_count: 0,
                commitment: r.commitment
            },
            head: Some((7, h(C2)))
        }
    );

    // The move writes no marker; the revert leaves a pre-move marker as it is.
    let (_d, db) = production_shaped_database();
    set_head(&db, HEAD);
    assert_eq!(read_start_marker(&db).unwrap(), None);
    let pre = record_start(&db).unwrap();
    let before = all_rows(&db);
    let moved = move_to_schema_4(&db, HEAD);
    assert_eq!(
        read_start_marker(&db).unwrap(),
        Some(pre.clone()),
        "the move wrote none"
    );
    let p = ccfg::pending_schema_revert(&db).unwrap();
    assert_eq!(p.start_marker, Some(pre.clone()));
    assert_eq!(
        p.head_hash,
        sumchain_storage::schema::BlockStore::new(&db)
            .get_latest_hash()
            .unwrap()
    );
    ccfg::revert_schema_transition(&db, moved.to, moved.from).unwrap();
    assert_eq!(all_rows(&db), before, "every row, the marker included");
    assert_eq!(read_start_marker(&db).unwrap(), Some(pre));
}

/// A marker written at the move's own transition count means a node started
/// on the moved record: the revert refuses, whatever else the start did or did
/// not write, and writes nothing. A marker written before the move (at a
/// lower count that the history accounts for) does not.
#[test]
fn a_start_marker_at_the_move_refuses_the_revert() {
    let (_d, db) = production_shaped_database();
    set_head(&db, HEAD);
    let moved = move_to_schema_4(&db, HEAD);
    assert!(ccfg::pending_schema_revert(&db).is_ok());
    // What a normal start leaves first, before anything else, whether it then
    // runs, imports nothing, or is refused.
    let m = record_start(&db).unwrap();
    assert_eq!(
        m.record,
        RecordState::Present {
            transition_count: moved.seq,
            commitment: moved.to
        }
    );
    let before = all_rows(&db);
    for attempt in 0..2 {
        let err = ccfg::revert_schema_transition(&db, moved.to, moved.from).unwrap_err();
        assert!(matches!(err, ConfigError::Refused(_)), "{attempt}: {err}");
        let text = err.to_string();
        assert!(
            text.contains("a normal start was attempted on the moved record"),
            "{text}"
        );
        assert!(text.contains("forward only"), "{text}");
        assert!(text.contains(&format!("attempt {}", m.attempt)), "{text}");
        let err = ccfg::pending_schema_revert(&db).unwrap_err();
        assert!(
            err.to_string().contains("a normal start was attempted"),
            "{err}"
        );
    }
    assert_eq!(all_rows(&db), before, "nothing written");
    // The chain position alone would have allowed it: the marker is the reason.
    assert_eq!(
        sumchain_storage::schema::BlockStore::new(&db)
            .get_latest_height()
            .unwrap(),
        Some(HEAD)
    );
}

/// A marker this history cannot account for — a count above the record's, a
/// commitment the history does not hold at its count, a start made while the
/// record was absent or unreadable, or bytes this binary cannot read — is an
/// uncertain state: the revert refuses and writes nothing.
#[test]
fn an_inconsistent_or_unreadable_start_marker_refuses_the_revert_as_uncertain() {
    fn put_marker(db: &Database, m: &StartMarker) {
        // Written as `record_start` writes it, through the one encoder, by
        // recording a start and then rewriting the row with the wanted content.
        record_start(db).unwrap();
        let raw = db.get(cf::META, START_MARKER_KEY).unwrap().unwrap();
        let mut out = raw.clone();
        out[2..10].copy_from_slice(&m.attempt.to_le_bytes());
        let (state, count, commitment) = match m.record {
            RecordState::Absent => (0u8, 0u64, Hash::default()),
            RecordState::Present {
                transition_count,
                commitment,
            } => (1, transition_count, commitment),
            RecordState::Unreadable => (2, 0, Hash::default()),
        };
        out[10] = state;
        out[11..19].copy_from_slice(&count.to_le_bytes());
        out[19..51].copy_from_slice(commitment.as_bytes());
        db.put(cf::META, START_MARKER_KEY, &out).unwrap();
        assert_eq!(read_start_marker(db).unwrap().unwrap().record, m.record);
    }
    let (_d, db) = production_shaped_database();
    set_head(&db, HEAD);
    let moved = move_to_schema_4(&db, HEAD);
    let r = ccfg::read_record(&db).unwrap().unwrap();
    let zero = Hash::default();
    let cases: Vec<(&str, StartMarker)> = vec![
        (
            "count above the record's",
            StartMarker {
                attempt: 1,
                record: RecordState::Present {
                    transition_count: r.transition_count + 1,
                    commitment: moved.to,
                },
                head: None,
            },
        ),
        (
            "wrong commitment at the previous count",
            StartMarker {
                attempt: 1,
                record: RecordState::Present {
                    transition_count: moved.seq - 1,
                    commitment: zero,
                },
                head: None,
            },
        ),
        (
            "wrong commitment at the move's count",
            StartMarker {
                attempt: 1,
                record: RecordState::Present {
                    transition_count: moved.seq,
                    commitment: zero,
                },
                head: None,
            },
        ),
        (
            "started while the record was absent",
            StartMarker {
                attempt: 1,
                record: RecordState::Absent,
                head: None,
            },
        ),
        (
            "started while the record was unreadable",
            StartMarker {
                attempt: 1,
                record: RecordState::Unreadable,
                head: None,
            },
        ),
    ];
    for (what, m) in cases {
        put_marker(&db, &m);
        let before = all_rows(&db);
        let err = ccfg::revert_schema_transition(&db, moved.to, moved.from).unwrap_err();
        assert!(matches!(err, ConfigError::Refused(_)), "{what}: {err}");
        assert!(
            err.to_string().contains("uncertain migration state"),
            "{what}: {err}"
        );
        assert!(ccfg::pending_schema_revert(&db).is_err(), "{what}");
        assert_eq!(all_rows(&db), before, "{what}: nothing written");
    }
    // Bytes this binary cannot read: a newer version, and garbage.
    for (what, raw) in [
        ("a newer marker version", {
            let mut raw = db.get(cf::META, START_MARKER_KEY).unwrap().unwrap();
            raw[0] = 2;
            raw
        }),
        ("garbage", b"not a marker".to_vec()),
    ] {
        db.put(cf::META, START_MARKER_KEY, &raw).unwrap();
        let before = all_rows(&db);
        assert!(read_start_marker(&db).is_err(), "{what}");
        let err = ccfg::revert_schema_transition(&db, moved.to, moved.from).unwrap_err();
        assert!(matches!(err, ConfigError::Refused(_)), "{what}: {err}");
        assert!(
            err.to_string().contains("uncertain migration state"),
            "{what}: {err}"
        );
        assert!(err.to_string().contains("unreadable"), "{what}: {err}");
        // A start refuses too, rather than overwrite what it cannot read.
        let err = record_start(&db).unwrap_err();
        assert!(err.to_string().contains("unreadable"), "{what}: {err}");
        assert_eq!(all_rows(&db), before, "{what}: nothing written");
    }
}

/// A marker that predates the move by more than one transition is accounted
/// for through the history, so the revert of a later move is allowed: a node
/// that ran on an earlier record, was moved, and was never started since.
#[test]
fn a_start_marker_from_before_the_move_is_accounted_for_through_the_history() {
    // Started at transition count 0 (the fixture's first record).
    let (_d, db) = schema_1_database();
    set_head(&db, HEAD);
    // The fixture holds three transitions; a marker at count 0 is checked
    // against the initial commitment.
    let r = ccfg::read_record(&db).unwrap().unwrap();
    record_start(&db).unwrap();
    let raw = db.get(cf::META, START_MARKER_KEY).unwrap().unwrap();
    let mut early = raw.clone();
    early[11..19].copy_from_slice(&0u64.to_le_bytes());
    early[19..51].copy_from_slice(r.initial_commitment.as_bytes());
    db.put(cf::META, START_MARKER_KEY, &early).unwrap();
    let before = all_rows(&db);
    let moved = move_to_schema_4(&db, HEAD);
    let p = ccfg::pending_schema_revert(&db).unwrap();
    assert_eq!(p.seq, moved.seq);
    ccfg::revert_schema_transition(&db, moved.to, moved.from).unwrap();
    assert_eq!(all_rows(&db), before);
}

/// The source tripwire for durability: the move, the revert and the start
/// marker commit with the write-ahead log synced (`commit_durable`), never with
/// the plain commit. A killed process cannot tell the two apart, so the text
/// is checked.
#[test]
fn the_move_the_revert_and_the_start_marker_commit_durably() {
    let record_src = include_str!("../src/consensus_config/record.rs");
    let marker_src = include_str!("../src/consensus_config/start_marker.rs");
    let body_of = |src: &str, head: &str| -> String {
        let start = src.find(head).unwrap_or_else(|| panic!("{head} not found"));
        let rest = &src[start..];
        // Up to the next top-level item.
        let end = rest[1..]
            .find("\n}\n")
            .map(|i| i + 1 + 3)
            .unwrap_or(rest.len());
        rest[..end].to_string()
    };
    for (src, head) in [
        (record_src, "fn write_transition("),
        (record_src, "pub fn revert_schema_transition_with("),
        (marker_src, "pub fn record_start("),
    ] {
        let body = body_of(src, head);
        assert!(body.contains(".commit_durable()"), "{head}: not durable");
        assert!(!body.contains(".commit()"), "{head}: a plain commit");
        assert_eq!(
            body.matches("commit_durable").count(),
            1,
            "{head}: one commit"
        );
    }
    // And `write_initial`, the fresh baseline, as before.
    assert!(body_of(record_src, "fn write_initial(").contains(".commit_durable()"));
}

// ── the handshake digest of #350 B2, and the move ───────────────────────────

/// The handshake digest that public PR #384 (B2, `consensus_config/handshake.rs`)
/// declares at connect, computed
/// here exactly as that source defines it:
///
/// ```text
/// BLAKE3( "sumchain/protocol-digest/v2" ‖ protocol_digest(genesis) ‖ build(genesis).commitment() )
/// ```
///
/// 27 + 32 + 32 = 91 bytes; `build(genesis)` is the RUNNING configuration, in
/// the schema the binary writes, never the recorded one.
fn b2_handshake_digest(g: &Genesis, policy: &SchemaPolicy) -> ([u8; 91], Hash) {
    let pd = sumchain_state::protocol_digest::protocol_digest(g).unwrap();
    let running = ccfg::build_with(g, policy).unwrap();
    let mut preimage = [0u8; 91];
    preimage[..27].copy_from_slice(b"sumchain/protocol-digest/v2");
    preimage[27..59].copy_from_slice(pd.as_bytes());
    preimage[59..].copy_from_slice(running.commitment().as_bytes());
    (preimage, Hash::hash(&preimage))
}

/// How the three digests relate to this change, as B2 defines them:
///
/// * the activation digest folds the gate names and heights; the protocol
///   digest folds it with the compiled limits; neither reads the stored
///   record, so the move changes neither;
/// * B2's handshake digest folds the protocol digest and the RUNNING
///   commitment (`build(genesis)` in `PRODUCTION.writes`). Changing the
///   binary's written-schema policy (3 → 4) changes that commitment and so the
///   handshake digest; moving the stored record alone does not;
/// * the same binary and genesis declare the same handshake digest whatever
///   the recorded-schema history: a fresh schema-4 record, a schema-3 record
///   moved, a schema-3 record left as it stands.
#[test]
fn the_move_changes_the_recorded_commitment_but_not_what_b2_would_declare() {
    let g = g_ph();
    // The digests the move does not touch, measured before and after it.
    let (_d, db) = production_shaped_database();
    set_head(&db, HEAD);
    let activation_before = g.activation_digest().unwrap();
    let protocol_before = sumchain_state::protocol_digest::protocol_digest(&g).unwrap();
    let (preimage_before, handshake_before) = b2_handshake_digest(&g, &PRODUCTION);
    let recorded_before = ccfg::read_record(&db).unwrap().unwrap().commitment;
    let moved = move_to_schema_4(&db, HEAD);
    let recorded_after = ccfg::read_record(&db).unwrap().unwrap().commitment;
    assert_ne!(
        recorded_before, recorded_after,
        "the move changes the RECORDED commitment"
    );
    assert_eq!(recorded_after, moved.to);
    assert_eq!(g.activation_digest().unwrap(), activation_before);
    assert_eq!(
        sumchain_state::protocol_digest::protocol_digest(&g).unwrap(),
        protocol_before
    );
    let (preimage_after, handshake_after) = b2_handshake_digest(&g, &PRODUCTION);
    assert_eq!(
        preimage_after, preimage_before,
        "the preimage reads no record"
    );
    assert_eq!(handshake_after, handshake_before);

    // Three nodes, one binary, one genesis, three recorded histories: one
    // declaration. The RUNNING commitment is the schema-4 configuration of the
    // genesis on each; the recorded commitments differ.
    let fresh_dir = TempDir::new().unwrap();
    let fresh = Database::open_default(fresh_dir.path()).unwrap();
    assert!(matches!(
        ccfg::check_at_startup(&fresh, &g, HEAD).unwrap(),
        StartupOutcome::Initialized { .. }
    ));
    let (_d3, unmoved) = production_shaped_database();
    assert!(matches!(
        ccfg::check_at_startup(&unmoved, &g, HEAD).unwrap(),
        StartupOutcome::Unchanged { .. }
    ));
    assert!(matches!(
        ccfg::check_at_startup(&db, &g, HEAD).unwrap(),
        StartupOutcome::Unchanged { .. }
    ));
    let records: Vec<ccfg::BaselineRecord> = [&fresh, &db, &unmoved]
        .iter()
        .map(|d| ccfg::read_record(d).unwrap().unwrap())
        .collect();
    assert_eq!(
        records
            .iter()
            .map(|r| r.config.schema().number)
            .collect::<Vec<_>>(),
        [4, 4, 3]
    );
    assert_ne!(records[0].commitment, records[2].commitment);
    assert_eq!(
        records[0].commitment, records[1].commitment,
        "the same rules in schema 4"
    );
    let running = ccfg::build(&g).unwrap();
    for (i, r) in records.iter().enumerate() {
        // What `Node::new` would declare after each start: `build(genesis)`,
        // which equals the record carried into the written schema.
        assert_eq!(
            b2_handshake_digest(&g, &PRODUCTION).1,
            handshake_before,
            "node {i}"
        );
        let carried = if std::ptr::eq(r.config.schema(), running.schema()) {
            r.config.clone()
        } else {
            r.config.extend_to(running.schema()).unwrap()
        };
        assert_eq!(carried, running, "node {i} records the running rules");
    }

    // Changing the written-schema policy changes the running commitment and
    // therefore the handshake digest, with the protocol digest unchanged: the
    // schema-4 writer declares a different value from a schema-3 writer of the
    // same binary and genesis. That is the one cause B2's vectors move by.
    let (preimage_3, handshake_3) = b2_handshake_digest(&g, &SCHEMA_3_RELEASE);
    assert_eq!(
        preimage_3[..59],
        preimage_before[..59],
        "domain and protocol digest equal"
    );
    assert_ne!(
        preimage_3[59..],
        preimage_before[59..],
        "the running commitment differs"
    );
    assert_ne!(handshake_3, handshake_before);
    let three = ccfg::build_with(&g, &SCHEMA_3_RELEASE).unwrap();
    assert_eq!(three.extend_to(&SCHEMA_4).unwrap(), running);
    assert_eq!(preimage_before[59..], *running.commitment().as_bytes());
    assert_eq!(preimage_3[59..], *three.commitment().as_bytes());
}

/// B2's golden genesis (`handshake_digest.rs`, `golden_genesis`: chain 1,
/// one validator from key `[31; 32]`, `ChainParams::default()`), and what this
/// binary would declare for it. B2 pins its protocol digest, running
/// commitment and handshake digest; against B2's base all three move here, and
/// each for one stated cause:
///
/// * the protocol digest, because the signature and evidence gates declare
///   two more gate names (`0x1046`, `0x1047`), which the activation digest folds;
/// * the running commitment, because this binary writes schema 4: the
///   schema-3 encoding with schema number 4, field count + 4, and the four
///   gates' absent entries (28 bytes) after `0x1043`'s;
/// * the handshake digest, because both of its inputs moved.
///
/// The values are printed; the derivation is asserted.
#[test]
fn what_this_binary_would_declare_for_b2s_golden_genesis() {
    let v = KeyPair::from_bytes([31u8; 32]);
    let g = Genesis::new(
        1,
        1_734_624_000_000,
        vec![v.public_key().to_base58()],
        std::collections::HashMap::from([(v.address().to_base58(), 1_000_000u128)]),
        ChainParams::default(),
    );
    let pd = sumchain_state::protocol_digest::protocol_digest(&g).unwrap();
    let four = ccfg::build(&g).unwrap();
    let three = ccfg::build_with(&g, &SCHEMA_3_RELEASE).unwrap();
    let (preimage, handshake) = b2_handshake_digest(&g, &PRODUCTION);
    // The running commitment's preimage: the schema-3 bytes with the header
    // and the four absent entries.
    let b3 = three.encode();
    let b4 = four.encode();
    assert_eq!(b4.len(), b3.len() + 28);
    assert_eq!(&b4[..7], &b3[..7]);
    assert_eq!(u16::from_le_bytes([b4[7], b4[8]]), 4);
    assert_eq!(
        u16::from_le_bytes([b4[9], b4[10]]),
        u16::from_le_bytes([b3[9], b3[10]]) + 4
    );
    let at = b3
        .windows(7)
        .position(|w| w == [0x43, 0x10, 0, 0, 0, 0, 0])
        .unwrap()
        + 7;
    assert_eq!(&b4[11..at], &b3[11..at]);
    assert_eq!(
        &b4[at..at + 28],
        &[
            0x44, 0x10, 0, 0, 0, 0, 0, 0x45, 0x10, 0, 0, 0, 0, 0, 0x46, 0x10, 0, 0, 0, 0, 0, 0x47,
            0x10, 0, 0, 0, 0, 0
        ]
    );
    assert_eq!(&b4[at + 28..], &b3[at..]);
    assert_eq!(&preimage[59..], four.commitment().as_bytes());
    eprintln!(
        "B2-GOLDEN\tprotocol_digest={pd}\trunning_commitment_schema4={}\trunning_commitment_schema3={}\thandshake_digest={handshake}",
        four.commitment(),
        three.commitment()
    );
}
