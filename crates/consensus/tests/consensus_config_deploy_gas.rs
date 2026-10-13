//! #279: `max_contract_deploy_gas` (`0x0116`) in the schema-2 registry.
//!
//! A U64 parameter, absent unless set: absent, deploys stay bounded by
//! `max_contract_gas`. Its value rules (`schema::check_metering_relations`) hold
//! on every build and decode: present only with the metering gate (`0x1041`),
//! at least `max_contract_gas` (`0x0106`), and at most a present block budget
//! (`0x0115`).

use sumchain_consensus::consensus_config::{
    self as ccfg,
    fields::Ty,
    schema::{
        Source, CONTRACT_METERING_GATE_ID, MAX_BLOCK_CONTRACT_GAS_ID, MAX_CONTRACT_DEPLOY_GAS_ID,
        METERED_COST_SCHEDULE_ID, METERED_ENGINE_IDENTITY_ID, SCHEMA_2_ADDED,
    },
    ConfigError, ConsensusConfig, SchemaPolicy, Value, SCHEMA_1, SCHEMA_2,
};
use sumchain_crypto::KeyPair;
use sumchain_genesis::{ChainParams, Genesis};

const DEPLOY: u16 = MAX_CONTRACT_DEPLOY_GAS_ID;

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

fn tx() -> u64 {
    genesis().params.max_contract_gas
}

#[test]
fn it_is_registered_as_an_optional_u64_parameter() {
    assert_eq!(DEPLOY, 0x0116);
    let added = SCHEMA_2_ADDED
        .iter()
        .find(|a| a.spec.id == DEPLOY)
        .expect("registered");
    let s = added.spec;
    assert_eq!(
        (s.name, s.ty, s.optional, s.item_width),
        ("max_contract_deploy_gas", Ty::U64, true, None)
    );
    assert!(matches!(added.source, Source::Param(_)));
}

#[test]
fn dormant_it_is_absent_and_set_without_the_gate_it_is_never_built() {
    let c = ccfg::build_with(&genesis(), &ENABLED).unwrap();
    assert_eq!(c.get(DEPLOY), Some(&Value::Absent));
    let mut g = genesis();
    g.params.max_contract_deploy_gas = Some(2 * tx());
    let err = ccfg::build_with(&g, &ENABLED).unwrap_err();
    assert!(matches!(err, ConfigError::Malformed(_)), "{err}");
    let err = ccfg::build_with(&g, &SCHEMA_1_BINARY).unwrap_err();
    assert!(err.to_string().contains("max_contract_deploy_gas"), "{err}");
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

/// The dormant schema-2 encoding with the metering gate, budget and deploy
/// ceiling replaced (`None` leaves a field absent). When the gate is set, the
/// identity and schedule carry TEST_ONLY values in their registered shapes.
fn encoding_with(gate: Option<u64>, budget: Option<u64>, deploy: Option<u64>) -> Vec<u8> {
    let base = ccfg::build_with(&genesis(), &ENABLED).unwrap().encode();
    let schedule = {
        let tag = b"TEST-ONLY-schedule";
        let mut v = vec![tag.len() as u8];
        v.extend_from_slice(tag);
        v.push(1);
        v
    };
    let u64v = |v: Option<u64>| v.map_or((0, vec![]), |x| (1, x.to_le_bytes().to_vec()));
    let mut out = base[..11].to_vec();
    for (id, tag, value) in parse(&base) {
        let (tag, value) = match id {
            CONTRACT_METERING_GATE_ID => u64v(gate),
            MAX_BLOCK_CONTRACT_GAS_ID => u64v(budget),
            MAX_CONTRACT_DEPLOY_GAS_ID => u64v(deploy),
            METERED_ENGINE_IDENTITY_ID if gate.is_some() => (4, b"TEST-ONLY-engine".to_vec()),
            METERED_COST_SCHEDULE_ID if gate.is_some() => (4, schedule.clone()),
            _ => (tag, value),
        };
        out.extend_from_slice(&id.to_le_bytes());
        out.push(tag);
        out.extend_from_slice(&(value.len() as u32).to_le_bytes());
        out.extend_from_slice(&value);
    }
    out
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
fn consistent_metered_encodings_decode() {
    for (budget, deploy) in [
        (None, None),
        (None, Some(tx())),
        (None, Some(u64::MAX)),
        (Some(2 * tx()), Some(2 * tx())),
        (Some(u64::MAX), Some(2 * tx())),
    ] {
        let bytes = encoding_with(Some(1_000), budget, deploy);
        let c = decode(&bytes).unwrap_or_else(|e| panic!("{budget:?} {deploy:?}: {e}"));
        assert_eq!(
            c.get(DEPLOY),
            Some(&deploy.map_or(Value::Absent, Value::U64))
        );
        assert_eq!(c.encode(), bytes);
    }
}

#[test]
fn it_needs_the_gate() {
    assert_malformed(
        &encoding_with(None, None, Some(2 * tx())),
        "while the metering gate",
    );
}

#[test]
fn it_is_at_least_the_per_transaction_ceiling() {
    for deploy in [0, tx() - 1] {
        assert_malformed(
            &encoding_with(Some(1), None, Some(deploy)),
            "is below max_contract_gas",
        );
    }
}

#[test]
fn a_present_block_budget_is_at_least_it() {
    assert_malformed(
        &encoding_with(Some(1), Some(2 * tx() - 1), Some(2 * tx())),
        "(contract deploy gas ceiling)",
    );
}
