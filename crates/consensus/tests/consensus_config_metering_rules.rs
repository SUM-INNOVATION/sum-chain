//! #279: the metering fields' value rules (`schema::check_metering_relations`),
//! exercised one by one on decode, and their absent encoding.
//!
//! `consensus_config_metering.rs` covers registration, dormancy, persistence,
//! the transition, the refusal while values are unratified, and a ratified
//! stand-in. This file adds what a decoded record must satisfy: a record that
//! breaks any rule was not produced by an encoder and is refused, and a
//! well-formed metered configuration at every bound is accepted.

use sumchain_consensus::consensus_config::{
    self as ccfg,
    schema::{
        CONTRACT_METERING_GATE_ID, MAX_BLOCK_CONTRACT_GAS_ID, METERED_COST_SCHEDULE_ID,
        METERED_COST_SCHEDULE_TAG_MAX_LEN, METERED_ENGINE_IDENTITY_ID,
        METERED_ENGINE_IDENTITY_MAX_LEN,
    },
    ConfigError, ConsensusConfig, SchemaPolicy, Value, SCHEMA_1, SCHEMA_2,
};
use sumchain_crypto::KeyPair;
use sumchain_genesis::{ChainParams, Genesis};

const GATE: u16 = CONTRACT_METERING_GATE_ID;
const BUDGET: u16 = MAX_BLOCK_CONTRACT_GAS_ID;
const IDENTITY: u16 = METERED_ENGINE_IDENTITY_ID;
const SCHEDULE: u16 = METERED_COST_SCHEDULE_ID;
const ALL: [u16; 4] = [GATE, BUDGET, IDENTITY, SCHEDULE];

/// The real schema 2 enabled, as the change that writes it would.
static ENABLED: SchemaPolicy = SchemaPolicy {
    reads: &[&SCHEMA_1, &SCHEMA_2],
    writes: &SCHEMA_2,
    knows: &ccfg::SCHEMA_3,
};

/// A binary that reads and writes schema 1 and knows schema 2 as a draft.
static SCHEMA_1_BINARY: SchemaPolicy = SchemaPolicy {
    reads: &[&SCHEMA_1],
    writes: &SCHEMA_1,
    knows: &ccfg::SCHEMA_3,
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

// ── absent encoding ─────────────────────────────────────────────────────────

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

#[test]
fn a_budget_without_the_gate_is_never_built() {
    let mut g = genesis();
    g.params.max_block_contract_gas = Some(u64::MAX);
    let err = ccfg::build_with(&g, &ENABLED).unwrap_err();
    assert!(matches!(err, ConfigError::Malformed(_)), "{err}");
    let err = ccfg::build_with(&g, &SCHEMA_1_BINARY).unwrap_err();
    assert!(err.to_string().contains("max_block_contract_gas"), "{err}");
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
