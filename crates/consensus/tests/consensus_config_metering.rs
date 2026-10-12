//! #279: how the four metering fields of schema 2 behave in a recorded
//! consensus configuration, under a policy that writes schema 2.
//!
//! * Dormant (gate unset): all four are absent; a record keeps them absent
//!   through restart and through the schema transition.
//! * Provisional values: setting the metering gate is refused when the
//!   configuration is built, so neither start nor an acknowledgement can
//!   record a provisional engine identity or cost schedule; nothing is written.
//! * Ratified values (a TEST_ONLY stand-in for the ratification change): the
//!   identity and schedule are committed as bytes, persist, and bind the
//!   commitment.

use std::cell::Cell;

use sumchain_consensus::consensus_config::{
    self as ccfg,
    fields::{FieldSpec, Ty},
    record::{
        acknowledge_schema_transition_with, acknowledge_with, check_at_startup_with,
        pending_schema_transition_with, read_record_with, RECORD_KEY,
    },
    schema::{
        CONTRACT_METERING_GATE_ID, MAX_BLOCK_CONTRACT_GAS_ID, METERED_COST_SCHEDULE_ID,
        METERED_COST_SCHEDULE_TAG_MAX_LEN, METERED_ENGINE_IDENTITY_ID,
        METERED_ENGINE_IDENTITY_MAX_LEN, SCHEMA_2_ADDED,
    },
    AddedField, ConfigError, ConsensusConfig, Schema, SchemaPolicy, Source, StartupOutcome, Value,
    SCHEMA_1, SCHEMA_2,
};
use sumchain_crypto::KeyPair;
use sumchain_genesis::{ChainParams, Genesis};
use sumchain_storage::{cf, Database};
use tempfile::TempDir;

const GATE: u16 = CONTRACT_METERING_GATE_ID;
const BUDGET: u16 = MAX_BLOCK_CONTRACT_GAS_ID;

/// The real schema 2 enabled, as the change that writes it would.
static ENABLED: SchemaPolicy = SchemaPolicy {
    reads: &[&SCHEMA_1, &SCHEMA_2],
    writes: &SCHEMA_2,
    knows: &SCHEMA_2,
};

/// A binary that reads and writes schema 1 and knows schema 2 as a draft.
static SCHEMA_1_BINARY: SchemaPolicy = SchemaPolicy {
    reads: &[&SCHEMA_1],
    writes: &SCHEMA_1,
    knows: &SCHEMA_2,
};

fn genesis() -> Genesis {
    let v = KeyPair::from_bytes([21u8; 32]);
    Genesis::new(
        1,
        1_734_624_000_000,
        vec![v.public_key().to_base58()],
        std::collections::HashMap::from([(v.address().to_base58(), 1_000_000u128)]),
        ChainParams::with_contracts_enabled(),
    )
}

fn with_gate(h: u64) -> Genesis {
    let mut g = genesis();
    g.params.contract_metering_enabled_from_height = Some(h);
    g
}

fn open(dir: &TempDir) -> Database {
    Database::open_default(dir.path()).unwrap()
}

fn entries(db: &Database) -> Vec<(Vec<u8>, Vec<u8>)> {
    db.prefix_iter_checked(cf::META, b"consensus_config/")
        .unwrap()
        .map(|e| e.unwrap())
        .take_while(|(k, _)| k.starts_with(b"consensus_config/"))
        .map(|(k, v)| (k.to_vec(), v.to_vec()))
        .collect()
}

fn spec(id: u16) -> &'static FieldSpec {
    &SCHEMA_2_ADDED
        .iter()
        .find(|a| a.spec.id == id)
        .unwrap_or_else(|| panic!("{id:#06x} is registered"))
        .spec
}

// ── registration: exact types and absence ───────────────────────────────────

#[test]
fn the_metering_fields_are_registered_with_exact_types() {
    let expect: [(u16, &str, Ty, bool); 4] = [
        (GATE, "contract_metering_enabled_from_height", Ty::U64, true),
        (BUDGET, "max_block_contract_gas", Ty::U64, false),
        (
            METERED_ENGINE_IDENTITY_ID,
            "sumc_runtime::metering::METERED_ENGINE_IDENTITY",
            Ty::Bytes,
            false,
        ),
        (
            METERED_COST_SCHEDULE_ID,
            "sumc_runtime::metering::METERED_COST_SCHEDULE",
            Ty::Bytes,
            false,
        ),
    ];
    for (id, name, ty, is_gate) in expect {
        let s = spec(id);
        assert_eq!(
            (s.name, s.ty, s.optional, s.item_width),
            (name, ty, true, None)
        );
        let added = SCHEMA_2_ADDED.iter().find(|a| a.spec.id == id).unwrap();
        assert_eq!(matches!(added.source, Source::Gate), is_gate, "{name}");
    }
    assert!(!sumc_runtime::metering::METERING_VALUES_RATIFIED);
    assert_eq!(
        sumc_runtime::metering::METERED_COST_SCHEDULE,
        sumc_runtime::metering::CostScheduleV1Provisional::PROVISIONAL
    );
    // The compiled values already have the registered shapes
    // (`schema::check_metering_relations`); only ratification is missing.
    let identity = sumc_runtime::metering::METERED_ENGINE_IDENTITY.as_bytes();
    assert!(!identity.is_empty() && identity.len() <= METERED_ENGINE_IDENTITY_MAX_LEN);
    assert!(identity.iter().all(|c| (0x21..=0x7e).contains(c)));
    let schedule = sumc_runtime::metering::METERED_COST_SCHEDULE.encode();
    let tag_len = schedule[0] as usize;
    assert!((1..=METERED_COST_SCHEDULE_TAG_MAX_LEN).contains(&tag_len));
    assert_eq!(&schedule[1..=tag_len], b"sumc-cost-v1-provisional");
    assert!(schedule.len() > 1 + tag_len);
}

#[test]
fn dormant_the_metering_fields_are_absent() {
    let c = ccfg::build_with(&genesis(), &ENABLED).unwrap();
    for id in [
        GATE,
        BUDGET,
        METERED_ENGINE_IDENTITY_ID,
        METERED_COST_SCHEDULE_ID,
    ] {
        assert_eq!(c.get(id), Some(&Value::Absent), "{id:#06x}");
    }
}

// ── persistence of a dormant configuration ─────────────────────────────────

#[test]
fn a_dormant_configuration_persists_and_restarts_with_the_metering_fields_absent() {
    let dir = TempDir::new().unwrap();
    let db = open(&dir);
    let g = genesis();
    let out = check_at_startup_with(&db, &g, 0, &ENABLED).unwrap();
    let StartupOutcome::Initialized { commitment, .. } = out else {
        panic!("{out:?}")
    };
    let r = read_record_with(&db, &ENABLED).unwrap().unwrap();
    assert_eq!(r.config.schema().number, 2);
    for id in [
        GATE,
        BUDGET,
        METERED_ENGINE_IDENTITY_ID,
        METERED_COST_SCHEDULE_ID,
    ] {
        assert_eq!(r.config.get(id), Some(&Value::Absent), "{id:#06x}");
    }
    drop(db);
    let db = open(&dir);
    assert_eq!(
        check_at_startup_with(&db, &g, 10, &ENABLED).unwrap(),
        StartupOutcome::Unchanged { commitment }
    );
}

#[test]
fn the_schema_transition_adds_the_metering_fields_absent() {
    let dir = TempDir::new().unwrap();
    let db = open(&dir);
    let g = genesis();
    check_at_startup_with(&db, &g, 0, &SCHEMA_1_BINARY).unwrap();
    let pending = pending_schema_transition_with(&db, &ENABLED)
        .unwrap()
        .expect("schema 2 offered");
    let done =
        acknowledge_schema_transition_with(&db, 0, pending.old, pending.new, &ENABLED).unwrap();
    for id in [
        GATE,
        BUDGET,
        METERED_ENGINE_IDENTITY_ID,
        METERED_COST_SCHEDULE_ID,
    ] {
        assert!(done.added.contains(&id), "{id:#06x}");
    }
    assert_eq!(
        check_at_startup_with(&db, &g, 0, &ENABLED).unwrap(),
        StartupOutcome::Unchanged {
            commitment: pending.new
        }
    );
}

// ── provisional values are never accepted ───────────────────────────────────

fn assert_unratified(err: &ConfigError) {
    let msg = err.to_string();
    assert!(matches!(err, ConfigError::Refused(_)), "{msg}");
    assert!(
        msg.contains("contract_metering_enabled_from_height"),
        "{msg}"
    );
    assert!(msg.contains("not ratified"), "{msg}");
}

#[test]
fn setting_the_gate_with_provisional_values_refuses_every_build() {
    for policy in [&ENABLED, &SCHEMA_1_BINARY, &ccfg::PRODUCTION] {
        for h in [0, 1, 1_000, u64::MAX] {
            assert_unratified(&ccfg::build_with(&with_gate(h), policy).unwrap_err());
        }
    }
}

#[test]
fn a_fresh_database_records_nothing_when_the_gate_is_set() {
    let dir = TempDir::new().unwrap();
    let db = open(&dir);
    let err = check_at_startup_with(&db, &with_gate(1_000), 0, &ENABLED).unwrap_err();
    assert_unratified(&err);
    assert_eq!(read_record_with(&db, &ENABLED).unwrap(), None);
    assert!(entries(&db).is_empty(), "nothing persisted");
    assert_eq!(db.get(cf::META, RECORD_KEY).unwrap(), None);
}

#[test]
fn an_existing_record_is_not_moved_by_a_provisional_gate() {
    let dir = TempDir::new().unwrap();
    let db = open(&dir);
    let g = genesis();
    let StartupOutcome::Initialized { commitment, .. } =
        check_at_startup_with(&db, &g, 0, &ENABLED).unwrap()
    else {
        panic!()
    };
    let before = entries(&db);
    let set = with_gate(1_000);
    assert_unratified(&check_at_startup_with(&db, &set, 0, &ENABLED).unwrap_err());
    // The acknowledgement computes the same configuration and refuses too,
    // whatever commitment it is told.
    for new in [commitment, sumchain_primitives::Hash::hash(b"anything")] {
        assert_unratified(&acknowledge_with(&db, &set, 0, commitment, new, &ENABLED).unwrap_err());
    }
    assert_eq!(entries(&db), before, "nothing rewritten");
}

// ── ratified values (TEST_ONLY stand-in for the ratification change) ────────

thread_local! {
    static SCHEDULE_VARIANT: Cell<u8> = const { Cell::new(0) };
}

const TEST_ONLY_IDENTITY: &[u8] = b"TEST-ONLY-ratified-engine";

fn test_identity(g: &Genesis) -> Value {
    match g.params.contract_metering_enabled_from_height {
        None => Value::Absent,
        Some(_) => Value::Bytes(TEST_ONLY_IDENTITY.to_vec()),
    }
}

fn test_schedule(g: &Genesis) -> Value {
    match g.params.contract_metering_enabled_from_height {
        None => Value::Absent,
        Some(_) => {
            let mut s = sumc_runtime::metering::CostScheduleV1Provisional::PROVISIONAL;
            s.op_call += u64::from(SCHEDULE_VARIANT.with(|c| c.get()));
            Value::Bytes(s.encode())
        }
    }
}

/// The real schema 2 with the identity and schedule sources replaced by
/// TEST_ONLY ones, as a binary with ratified values would compute them.
const RATIFIED_ADDED_ARRAY: [AddedField; SCHEMA_2_ADDED.len()] = {
    let mut out = [SCHEMA_2_ADDED[0]; SCHEMA_2_ADDED.len()];
    let mut i = 0;
    while i < SCHEMA_2_ADDED.len() {
        out[i] = SCHEMA_2_ADDED[i];
        if out[i].spec.id == METERED_ENGINE_IDENTITY_ID {
            out[i].source = Source::Param(test_identity);
        } else if out[i].spec.id == METERED_COST_SCHEDULE_ID {
            out[i].source = Source::Param(test_schedule);
        }
        i += 1;
    }
    out
};

static RATIFIED_SCHEMA_2: Schema = Schema {
    number: 2,
    previous: Some(&SCHEMA_1),
    added: &RATIFIED_ADDED_ARRAY,
};

static RATIFIED: SchemaPolicy = SchemaPolicy {
    reads: &[&SCHEMA_1, &RATIFIED_SCHEMA_2],
    writes: &RATIFIED_SCHEMA_2,
    knows: &RATIFIED_SCHEMA_2,
};

#[test]
fn ratified_values_are_committed_persist_and_bind_the_commitment() {
    SCHEDULE_VARIANT.with(|c| c.set(0));
    let g = with_gate(1_000);
    let c = ccfg::build_with(&g, &RATIFIED).unwrap();
    assert_eq!(c.get(GATE), Some(&Value::U64(1_000)));
    assert_eq!(
        c.get(METERED_ENGINE_IDENTITY_ID),
        Some(&Value::Bytes(TEST_ONLY_IDENTITY.to_vec()))
    );
    let Some(Value::Bytes(schedule)) = c.get(METERED_COST_SCHEDULE_ID) else {
        panic!("schedule committed")
    };
    assert_eq!(
        *schedule,
        sumc_runtime::metering::CostScheduleV1Provisional::PROVISIONAL.encode()
    );
    // The registry is the real one: the bytes decode under the real schema 2,
    // whose value rules they meet.
    let decoded = ConsensusConfig::decode_with(&c.encode(), &[&SCHEMA_1, &SCHEMA_2]).unwrap();
    assert_eq!(decoded.encode(), c.encode());

    // Persisted and read back exactly; a restart is unchanged.
    let dir = TempDir::new().unwrap();
    let db = open(&dir);
    check_at_startup_with(&db, &g, 0, &RATIFIED).unwrap();
    let r = read_record_with(&db, &RATIFIED).unwrap().unwrap();
    assert_eq!(r.config, c);
    assert_eq!(
        check_at_startup_with(&db, &g, 0, &RATIFIED).unwrap(),
        StartupOutcome::Unchanged {
            commitment: c.commitment()
        }
    );

    // A different schedule is a different commitment, refused at start as a
    // change that is not a gate.
    SCHEDULE_VARIANT.with(|c| c.set(1));
    let moved = ccfg::build_with(&g, &RATIFIED).unwrap();
    assert_ne!(moved.commitment(), c.commitment());
    let err = check_at_startup_with(&db, &g, 0, &RATIFIED).unwrap_err();
    assert!(err.to_string().contains("METERED_COST_SCHEDULE"), "{err}");
    SCHEDULE_VARIANT.with(|c| c.set(0));

    // The same genesis without the gate: every metering field absent again.
    let dormant = ccfg::build_with(&genesis(), &RATIFIED).unwrap();
    for id in [
        GATE,
        BUDGET,
        METERED_ENGINE_IDENTITY_ID,
        METERED_COST_SCHEDULE_ID,
    ] {
        assert_eq!(dormant.get(id), Some(&Value::Absent), "{id:#06x}");
    }
}
