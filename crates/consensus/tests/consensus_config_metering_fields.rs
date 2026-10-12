//! #279: the four contract-metering fields schema 2 registers, as encoded and
//! checked by a binary that has no metered engine.
//!
//! * Registration: exact ids, names, types and sources.
//! * Dormant: all four are absent; a record keeps them absent through restart
//!   and through the schema transition.
//! * Refusal: a configuration that sets the metering gate is refused when it
//!   is built, so neither start nor an acknowledgement records anything.
//! * Value rules ([`schema::check_metering_relations`]): a decoded record that
//!   breaks one is refused; a well-formed configuration with every metering
//!   field set (TEST_ONLY values standing in for a later ratified binary)
//!   builds, persists and decodes.

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
const IDENTITY: u16 = METERED_ENGINE_IDENTITY_ID;
const SCHEDULE: u16 = METERED_COST_SCHEDULE_ID;
const ALL: [u16; 4] = [GATE, BUDGET, IDENTITY, SCHEDULE];

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
            IDENTITY,
            "sumc_runtime::metering::METERED_ENGINE_IDENTITY",
            Ty::Bytes,
            false,
        ),
        (
            SCHEDULE,
            "sumc_runtime::metering::METERED_COST_SCHEDULE",
            Ty::Bytes,
            false,
        ),
    ];
    assert_eq!(ALL, [0x1041, 0x0115, 0x2716, 0x2717]);
    for (id, name, ty, is_gate) in expect {
        let s = spec(id);
        assert_eq!(
            (s.name, s.ty, s.optional, s.item_width),
            (name, ty, true, None)
        );
        let added = SCHEMA_2_ADDED.iter().find(|a| a.spec.id == id).unwrap();
        assert_eq!(matches!(added.source, Source::Gate), is_gate, "{name}");
    }
    assert_eq!(METERED_ENGINE_IDENTITY_MAX_LEN, 128);
    assert_eq!(METERED_COST_SCHEDULE_TAG_MAX_LEN, 64);
}

/// Absent is encoded as every optional field's absence is: the id, tag 0 and
/// length 0, with no value bytes.
#[test]
fn dormant_the_metering_fields_are_absent_and_encode_as_absent() {
    let c = ccfg::build_with(&genesis(), &ENABLED).unwrap();
    for id in ALL {
        assert_eq!(c.get(id), Some(&Value::Absent), "{id:#06x}");
    }
    let fields = parse(&c.encode());
    for id in ALL {
        let (_, tag, value) = fields.iter().find(|(i, _, _)| *i == id).unwrap();
        assert_eq!((*tag, value.len()), (0, 0), "{id:#06x}");
    }
    // Dormant schema 2 is schema 1 carried forward: the same rules.
    let one = ccfg::build_with(&genesis(), &SCHEMA_1_BINARY).unwrap();
    assert_eq!(one.extend_to(&SCHEMA_2).unwrap(), c);
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
    for id in ALL {
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
    for id in ALL {
        assert!(done.added.contains(&id), "{id:#06x}");
    }
    assert_eq!(
        check_at_startup_with(&db, &g, 0, &ENABLED).unwrap(),
        StartupOutcome::Unchanged {
            commitment: pending.new
        }
    );
}

// ── the gate is refused: nothing can be recorded ───────────────────────────

fn assert_refused(err: &ConfigError) {
    let msg = err.to_string();
    assert!(matches!(err, ConfigError::Refused(_)), "{msg}");
    assert!(
        msg.contains("contract_metering_enabled_from_height"),
        "{msg}"
    );
    assert!(msg.contains("not ratified"), "{msg}");
}

#[test]
fn setting_the_gate_refuses_every_build() {
    for policy in [&ENABLED, &SCHEMA_1_BINARY, &ccfg::PRODUCTION] {
        for h in [0, 1, 1_000, u64::MAX] {
            assert_refused(&ccfg::build_with(&with_gate(h), policy).unwrap_err());
            let mut g = with_gate(h);
            g.params.max_block_contract_gas = Some(u64::MAX);
            assert_refused(&ccfg::build_with(&g, policy).unwrap_err());
        }
    }
}

#[test]
fn a_budget_without_the_gate_is_never_built() {
    let mut g = genesis();
    g.params.max_block_contract_gas = Some(u64::MAX);
    let err = ccfg::build_with(&g, &ENABLED).unwrap_err();
    assert!(matches!(err, ConfigError::Malformed(_)), "{err}");
    let err = ccfg::build_with(&g, &SCHEMA_1_BINARY).unwrap_err();
    assert!(err.to_string().contains("max_block_contract_gas"), "{err}");
}

#[test]
fn a_fresh_database_records_nothing_when_the_gate_is_set() {
    let dir = TempDir::new().unwrap();
    let db = open(&dir);
    let err = check_at_startup_with(&db, &with_gate(1_000), 0, &ENABLED).unwrap_err();
    assert_refused(&err);
    assert_eq!(read_record_with(&db, &ENABLED).unwrap(), None);
    assert!(entries(&db).is_empty(), "nothing persisted");
    assert_eq!(db.get(cf::META, RECORD_KEY).unwrap(), None);
}

#[test]
fn an_existing_record_is_not_moved_by_the_gate() {
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
    assert_refused(&check_at_startup_with(&db, &set, 0, &ENABLED).unwrap_err());
    // The acknowledgement computes the same configuration and refuses too,
    // whatever commitment it is told.
    for new in [commitment, sumchain_primitives::Hash::hash(b"anything")] {
        assert_refused(&acknowledge_with(&db, &set, 0, commitment, new, &ENABLED).unwrap_err());
    }
    assert_eq!(entries(&db), before, "nothing rewritten");
}

// ── value rules, on decode ──────────────────────────────────────────────────

/// `(id, tag, value)` of every field of an encoding, per the codec's layout.
fn parse(bytes: &[u8]) -> Vec<(u16, u8, Vec<u8>)> {
    let le16 = |b: &[u8]| u16::from_le_bytes([b[0], b[1]]);
    let count = le16(&bytes[9..11]) as usize;
    let mut pos = 11;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let id = le16(&bytes[pos..]);
        let tag = bytes[pos + 2];
        let len = u32::from_le_bytes(bytes[pos + 3..pos + 7].try_into().unwrap()) as usize;
        out.push((id, tag, bytes[pos + 7..pos + 7 + len].to_vec()));
        pos += 7 + len;
    }
    assert_eq!(pos, bytes.len());
    out
}

fn unparse(head: &[u8], fields: &[(u16, u8, Vec<u8>)]) -> Vec<u8> {
    let mut out = head[..11].to_vec();
    for (id, tag, value) in fields {
        out.extend_from_slice(&id.to_le_bytes());
        out.push(*tag);
        out.extend_from_slice(&(value.len() as u32).to_le_bytes());
        out.extend_from_slice(value);
    }
    out
}

const TEST_ONLY_IDENTITY: &[u8] = b"TEST-ONLY-metered-engine";

/// A well-formed TEST_ONLY schedule: `tag_len ‖ tag ‖ body`.
fn test_only_schedule(body: &[u8]) -> Vec<u8> {
    let tag = b"TEST-ONLY-schedule";
    let mut out = vec![tag.len() as u8];
    out.extend_from_slice(tag);
    out.extend_from_slice(body);
    out
}

fn ceiling() -> u64 {
    genesis().params.max_contract_gas
}

/// The dormant schema-2 encoding with the metering fields replaced.
/// `None` leaves a field absent.
fn encoding_with(
    gate: Option<u64>,
    budget: Option<u64>,
    identity: Option<&[u8]>,
    schedule: Option<&[u8]>,
) -> Vec<u8> {
    let base = ccfg::build_with(&genesis(), &ENABLED).unwrap().encode();
    let mut fields = parse(&base);
    for (id, tag, value) in fields.iter_mut() {
        let (t, v) = match *id {
            GATE => gate.map_or((0, vec![]), |h| (1, h.to_le_bytes().to_vec())),
            BUDGET => budget.map_or((0, vec![]), |b| (1, b.to_le_bytes().to_vec())),
            IDENTITY => identity.map_or((0, vec![]), |b| (4, b.to_vec())),
            SCHEDULE => schedule.map_or((0, vec![]), |b| (4, b.to_vec())),
            _ => continue,
        };
        *tag = t;
        *value = v;
    }
    unparse(&base, &fields)
}

fn decode(bytes: &[u8]) -> Result<ConsensusConfig, ConfigError> {
    ConsensusConfig::decode_with(bytes, &[&SCHEMA_1, &SCHEMA_2])
}

fn assert_malformed(bytes: &[u8], why: &str) {
    match decode(bytes) {
        Err(ConfigError::Malformed(m)) => assert!(m.contains(why), "{why}: {m}"),
        other => panic!("{why}: {other:?}"),
    }
}

#[test]
fn a_well_formed_metered_configuration_decodes() {
    let sched = test_only_schedule(&[1, 2, 3]);
    for budget in [None, Some(ceiling()), Some(u64::MAX)] {
        let bytes = encoding_with(Some(1_000), budget, Some(TEST_ONLY_IDENTITY), Some(&sched));
        let c = decode(&bytes).unwrap();
        assert_eq!(c.get(GATE), Some(&Value::U64(1_000)));
        assert_eq!(c.encode(), bytes);
    }
    // Every bound, at the bound.
    let longest_identity = vec![b'~'; METERED_ENGINE_IDENTITY_MAX_LEN];
    let mut longest_tag = vec![METERED_COST_SCHEDULE_TAG_MAX_LEN as u8];
    longest_tag.extend(vec![b'!'; METERED_COST_SCHEDULE_TAG_MAX_LEN]);
    longest_tag.push(0);
    let bytes = encoding_with(Some(0), None, Some(&longest_identity), Some(&longest_tag));
    decode(&bytes).unwrap();
}

#[test]
fn the_identity_and_schedule_are_present_exactly_when_the_gate_is() {
    let sched = test_only_schedule(&[1]);
    let id = Some(TEST_ONLY_IDENTITY);
    for (gate, identity, schedule) in [
        (Some(1), None, None),
        (Some(1), id, None),
        (Some(1), None, Some(&sched[..])),
        (None, id, Some(&sched[..])),
        (None, id, None),
        (None, None, Some(&sched[..])),
    ] {
        assert_malformed(
            &encoding_with(gate, None, identity, schedule),
            "committed exactly when the gate is",
        );
    }
}

#[test]
fn the_budget_needs_the_gate_and_at_least_the_transaction_ceiling() {
    let sched = test_only_schedule(&[1]);
    assert_malformed(
        &encoding_with(None, Some(u64::MAX), None, None),
        "while the metering gate",
    );
    assert_malformed(
        &encoding_with(
            Some(1),
            Some(ceiling() - 1),
            Some(TEST_ONLY_IDENTITY),
            Some(&sched),
        ),
        "below max_contract_gas",
    );
    assert_malformed(
        &encoding_with(Some(1), Some(0), Some(TEST_ONLY_IDENTITY), Some(&sched)),
        "below max_contract_gas",
    );
}

#[test]
fn the_identity_is_bounded_printable_ascii() {
    let sched = test_only_schedule(&[1]);
    let too_long = vec![b'a'; METERED_ENGINE_IDENTITY_MAX_LEN + 1];
    for bad in [
        &b""[..],
        b"has space",
        b"tab\t",
        b"\x7f",
        "é".as_bytes(),
        &too_long,
    ] {
        assert_malformed(
            &encoding_with(Some(1), None, Some(bad), Some(&sched)),
            "printable ASCII",
        );
    }
}

#[test]
fn the_schedule_is_a_tagged_non_empty_body() {
    let mut too_long_tag = vec![(METERED_COST_SCHEDULE_TAG_MAX_LEN + 1) as u8];
    too_long_tag.extend(vec![b'a'; METERED_COST_SCHEDULE_TAG_MAX_LEN + 2]);
    let bad: [&[u8]; 6] = [
        b"",            // no frame
        b"\x00body",    // empty tag
        b"\x03abc",     // no body
        b"\x05abc",     // tag longer than the value
        b"\x03a c\x01", // tag not printable
        &too_long_tag,  // tag above the bound
    ];
    for bad in bad {
        assert_malformed(
            &encoding_with(Some(1), None, Some(TEST_ONLY_IDENTITY), Some(bad)),
            "tag_len:u8",
        );
    }
}

// ── later finalized values (TEST_ONLY stand-in for a ratified binary) ───────

fn test_identity(g: &Genesis) -> Value {
    match g.params.contract_metering_enabled_from_height {
        None => Value::Absent,
        Some(_) => Value::Bytes(TEST_ONLY_IDENTITY.to_vec()),
    }
}

fn test_schedule(g: &Genesis) -> Value {
    match g.params.contract_metering_enabled_from_height {
        None => Value::Absent,
        Some(_) => Value::Bytes(test_only_schedule(&[0, 0, 0, 1])),
    }
}

/// The real schema 2 with the identity and schedule sources replaced by
/// TEST_ONLY ones, as a binary with ratified values would compute them.
const FINALIZED_ADDED_ARRAY: [AddedField; SCHEMA_2_ADDED.len()] = {
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

static FINALIZED_SCHEMA_2: Schema = Schema {
    number: 2,
    previous: Some(&SCHEMA_1),
    added: &FINALIZED_ADDED_ARRAY,
};

static FINALIZED: SchemaPolicy = SchemaPolicy {
    reads: &[&SCHEMA_1, &FINALIZED_SCHEMA_2],
    writes: &FINALIZED_SCHEMA_2,
    knows: &FINALIZED_SCHEMA_2,
};

#[test]
fn finalized_values_are_committed_persist_and_decode_under_the_real_schema() {
    let mut g = with_gate(1_000);
    g.params.max_block_contract_gas = Some(ceiling());
    let c = ccfg::build_with(&g, &FINALIZED).unwrap();
    assert_eq!(c.get(GATE), Some(&Value::U64(1_000)));
    assert_eq!(c.get(BUDGET), Some(&Value::U64(ceiling())));
    assert_eq!(
        c.get(IDENTITY),
        Some(&Value::Bytes(TEST_ONLY_IDENTITY.to_vec()))
    );
    assert_eq!(
        c.get(SCHEDULE),
        Some(&Value::Bytes(test_only_schedule(&[0, 0, 0, 1])))
    );
    // The registry is the real one: its bytes decode under the real schema 2.
    assert_eq!(decode(&c.encode()).unwrap().encode(), c.encode());

    let dir = TempDir::new().unwrap();
    let db = open(&dir);
    check_at_startup_with(&db, &g, 0, &FINALIZED).unwrap();
    let r = read_record_with(&db, &FINALIZED).unwrap().unwrap();
    assert_eq!(r.config, c);
    assert_eq!(
        check_at_startup_with(&db, &g, 0, &FINALIZED).unwrap(),
        StartupOutcome::Unchanged {
            commitment: c.commitment()
        }
    );
    // The same genesis without the gate or budget: every field absent again.
    let dormant = ccfg::build_with(&genesis(), &FINALIZED).unwrap();
    for id in ALL {
        assert_eq!(dormant.get(id), Some(&Value::Absent), "{id:#06x}");
    }
}
