//! ConsensusConfigV1 (#268): the encoding commits to exactly the rules that
//! run, the decoder accepts exactly what the encoder produces, and the local
//! baseline is recorded, compared, transitioned and protected as specified.

use std::collections::HashMap;

use serde_json::{json, Value as Json};
use sumchain_consensus::consensus_config::{
    self as ccfg,
    codec::{commitment_of, MAGIC},
    fields::{RuleNames, EXCLUDED_PARAMETERS},
    record::{RECORD_KEY, TRANSITION_PREFIX},
    schema::{METERED_COST_SCHEDULE_ID, METERED_ENGINE_IDENTITY_ID, SCHEMA_2_ADDED},
    AddedField, BaselineStatus, ConfigError, ConsensusConfig, Schema, SchemaPolicy, Source,
    StartupOutcome, TransitionKind, Value, SCHEMA_1, SCHEMA_2, SCHEMA_V1_FIELDS,
};
use sumchain_crypto::KeyPair;
use sumchain_genesis::{BeaconParamsConfig, ChainParams, DocClassParams, Genesis, MessagingParams};
use sumchain_primitives::beacon_schedule::BeaconSchedule;
use sumchain_primitives::{Address, GovernanceParams, Hash, StakingParams};
use sumchain_storage::{cf, Database};
use tempfile::TempDir;

// ── fixtures ────────────────────────────────────────────────────────────────

fn key(i: u8) -> KeyPair {
    KeyPair::from_bytes([i; 32])
}

fn address(i: u8) -> Address {
    key(i).address()
}

/// A genesis in which EVERY optional group and optional value is present, so
/// that each committed field can be moved on its own.
fn full_genesis() -> Genesis {
    let params = ChainParams {
        staking: Some(StakingParams::default()),
        messaging: Some(MessagingParams {
            registry_admin: Some(address(40).to_base58()),
            ..MessagingParams::default()
        }),
        docclass: Some(DocClassParams {
            admin: Some(address(41).to_base58()),
            max_credential_validity: 1_000,
            ..DocClassParams::default()
        }),
        governance: Some(GovernanceParams {
            validator_authority_threshold_bps: 6_000,
            quorum_bps: 3_000,
            pass_threshold_bps: 5_000,
            voting_period_blocks: 1_000,
            max_snapshot_holders: 100,
            proposal_bond: 1_000,
            treasury: Some(address(42)),
            min_koppa_for_eligibility: 10,
        }),
        beacon_params: Some(BeaconParamsConfig {
            f: 1,
            c: 1,
            t: 2,
            q_dkg: 3,
            n: 5,
        }),
        beacon_schedule: Some(BeaconSchedule {
            start_height: 1_000,
            epoch_length: 10_000,
            key_cutoff_offset: 100,
            deal_start_offset: 200,
            deal_cutoff_offset: 300,
            complaint_start_offset: 400,
            complaint_deadline_offset: 500,
        }),
        inference_settlement_dispute_threshold_bps: Some(100),
        ..ChainParams::default()
    };
    let mut alloc = HashMap::new();
    for i in 1..=4u8 {
        alloc.insert(address(i).to_base58(), 1_000u128 * i as u128);
    }
    Genesis::new(
        7,
        1_700_000_000_000,
        vec![
            key(1).public_key().to_base58(),
            key(2).public_key().to_base58(),
        ],
        alloc,
        params,
    )
}

fn commitment(g: &Genesis) -> Hash {
    ccfg::build(g).expect("builds").commitment()
}

/// Move the genesis parameter at `path` (dot-separated, under `params`) to a
/// different valid value, through the genesis's own JSON form.
fn moved(g: &Genesis, path: &str) -> Genesis {
    let mut v = serde_json::to_value(g).expect("serializes");
    let mut cur = &mut v["params"];
    let parts: Vec<&str> = path.split('.').collect();
    for p in &parts[..parts.len() - 1] {
        cur = &mut cur[*p];
    }
    let leaf = &mut cur[*parts.last().unwrap()];
    assert!(
        !matches!(leaf, Json::Object(_)),
        "{path} is a group, not a value"
    );
    *leaf = match leaf.take() {
        Json::Array(mut items) => {
            items.push(json!(address(98).to_base58()));
            Json::Array(items)
        }
        Json::Null => json!(7),
        Json::Bool(b) => json!(!b),
        Json::Number(n) => json!(n.as_u64().expect("u64-sized test value") + 1),
        Json::String(_) => json!(address(99).to_base58()),
        other => panic!("{path}: unexpected {other:?}"),
    };
    serde_json::from_value(v).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn changed_ids(a: &Genesis, b: &Genesis) -> Vec<u16> {
    let a = ccfg::build(a).unwrap();
    let b = ccfg::build(b).unwrap();
    a.diff(&b).unwrap().into_iter().map(|c| c.id).collect()
}

fn id_of(name: &str) -> u16 {
    SCHEMA_V1_FIELDS
        .iter()
        .find(|s| s.name == name)
        .unwrap_or_else(|| panic!("no field {name}"))
        .id
}

fn open(dir: &TempDir) -> Database {
    Database::open_default(dir.path()).expect("opens")
}

/// The binaries released before this one: they read and write schema 1, and
/// know schema 2 only as a draft whose fields must stay absent. It is also how
/// the frozen schema-1 encoding is pinned now that this binary writes schema 2
/// (a binary knowing only schema 1 cannot be built: it would not know the
/// schema-2 gates `ChainParams::activation_heights` lists).
static SCHEMA_2_DRAFT: SchemaPolicy = SchemaPolicy {
    reads: &[&SCHEMA_1],
    writes: &SCHEMA_1,
    knows: &SCHEMA_2,
};

/// TEST_ONLY compute-pool parameters (no proposed value): every cap 1,
/// everything else 0.
fn test_only_compute_pool_params() -> sumchain_primitives::compute_pool_params::ComputePoolParamsV1
{
    serde_json::from_value(json!({
        "b_offer": 0, "b_commit": 0, "b_check": 0,
        "c_layer": 0, "c_tok": 0, "c_sel": 0, "c_emit": 0,
        "accept_reimb": 0, "commit_verify_reimb": 0, "publish_reimb": 0,
        "observe_reimb": 0, "check_reimb": 0, "settle_reimb": 0, "reassign_reimb": 0,
        "max_work_units": 1, "max_generations": 1, "max_reprovisionable_units": 1,
        "max_attempts_per_unit": 1, "max_reassignments_per_file": 1,
        "k_susp": 0, "w_susp": 0, "s_susp": 0, "n_invite_max": 0,
        "max_retention_files_per_job": 1, "max_retention_updates_per_block": 1,
        "max_reverse_index_entries": 1, "output_availability_blocks": 200,
        "d_avail": 0, "d_ack": 0, "d_final": 0
    }))
    .unwrap()
}

/// [`full_genesis`] with every field schema 2 adds set. Built with
/// [`METERED_STAND_IN`]: this binary has no metered engine, so it refuses the
/// metering gate and never commits an engine identity or cost schedule.
fn full_schema_2_genesis() -> Genesis {
    let mut g = full_genesis();
    g.params.credential_schema_validation_enabled_from_height = Some(10_000);
    g.params.messaging_timestamp_units_enabled_from_height = Some(20_000);
    g.params.contract_error_rollback_enabled_from_height = Some(30_000);
    g.params.compute_pool_params = Some(test_only_compute_pool_params());
    g.params.contract_metering_enabled_from_height = Some(40_000);
    g.params.max_block_contract_gas = Some(g.params.max_contract_gas);
    g.params.max_contract_deploy_gas = Some(g.params.max_contract_gas);
    g
}

/// TEST_ONLY stand-ins for a metered engine's identity and cost schedule, in
/// the registered shapes (`schema::check_metering_relations`). No proposed value.
fn test_only_metered_identity(g: &Genesis) -> Value {
    match g.params.contract_metering_enabled_from_height {
        None => Value::Absent,
        Some(_) => Value::Bytes(b"TEST-ONLY-metered-engine".to_vec()),
    }
}

fn test_only_metered_schedule(g: &Genesis) -> Value {
    match g.params.contract_metering_enabled_from_height {
        None => Value::Absent,
        Some(_) => {
            let tag = b"TEST-ONLY-schedule";
            let mut v = vec![tag.len() as u8];
            v.extend_from_slice(tag);
            v.extend_from_slice(&[0, 0, 0, 1]);
            Value::Bytes(v)
        }
    }
}

/// The real schema 2 with the two metering value sources replaced by TEST_ONLY
/// ones: what a binary with a metered engine would compute.
const METERED_STAND_IN_ADDED: [AddedField; SCHEMA_2_ADDED.len()] = {
    let mut out = [SCHEMA_2_ADDED[0]; SCHEMA_2_ADDED.len()];
    let mut i = 0;
    while i < SCHEMA_2_ADDED.len() {
        out[i] = SCHEMA_2_ADDED[i];
        if out[i].spec.id == METERED_ENGINE_IDENTITY_ID {
            out[i].source = Source::Param(test_only_metered_identity);
        } else if out[i].spec.id == METERED_COST_SCHEDULE_ID {
            out[i].source = Source::Param(test_only_metered_schedule);
        }
        i += 1;
    }
    out
};

static METERED_STAND_IN_SCHEMA_2: Schema = Schema {
    number: 2,
    previous: Some(&SCHEMA_1),
    added: &METERED_STAND_IN_ADDED,
};

static METERED_STAND_IN: SchemaPolicy = SchemaPolicy {
    reads: &[&SCHEMA_1, &METERED_STAND_IN_SCHEMA_2],
    writes: &METERED_STAND_IN_SCHEMA_2,
    knows: &METERED_STAND_IN_SCHEMA_2,
};

/// [`full_schema_2_genesis`]'s configuration: every schema-2 field set.
fn full_schema_2_config() -> ConsensusConfig {
    ccfg::build_with(&full_schema_2_genesis(), &METERED_STAND_IN).unwrap()
}

// ── the rules encoded are the rules that run ────────────────────────────────

#[test]
fn the_encoded_rule_codes_describe_the_implemented_engine() {
    let c = ccfg::build(&full_genesis()).unwrap();
    // Literal codes, not the constants under test: a constant moved to claim a
    // rule that does not run must fail here.
    let code = |name: &str| c.get(id_of(name)).cloned();
    assert_eq!(code("engine"), Some(Value::U8(1)));
    assert_eq!(code("finality_rule"), Some(Value::U8(1)));
    assert_eq!(code("quorum_rule"), Some(Value::U8(0)));
    assert_eq!(code("fork_choice_rule"), Some(Value::U8(1)));
    assert_eq!(code("proposer_rule"), Some(Value::U8(1)));
    assert_eq!(code("membership_rule"), Some(Value::U8(1)));
    assert_eq!(code("unfinalized_rule"), Some(Value::U8(0)));
    assert_eq!(code("timestamp_rule"), Some(Value::U8(1)));
    assert_eq!(code("protocol_version"), Some(Value::U16(1)));

    // The numbers behind them are what the engine uses, not restatements.
    assert_eq!(
        code("max_reorg_walk"),
        Some(Value::U64(sumchain_consensus::poa::MAX_REORG_WALK))
    );
    assert_eq!(
        code("undo_retention_floor"),
        Some(Value::U64(sumchain_storage::pruner::UNDO_RETENTION_FLOOR))
    );
    assert_eq!(
        code("finality_depth"),
        Some(Value::U64(full_genesis().params.finality_depth))
    );
    // No wall-clock bound exists, and the encoding says so explicitly.
    assert_eq!(code("max_future_drift_ms"), Some(Value::Absent));

    // Current values only: certified finality, a quorum and a bounded
    // unfinalized distance are not claimed.
    let names = RuleNames::of(Some(&c));
    assert_eq!(names.engine, "proof-of-authority");
    assert_eq!(names.finality, "local-depth");
    assert_eq!(names.quorum, "none");
    assert_eq!(names.membership, "static-genesis");
    assert_eq!(names.unfinalized_production, "unbounded");
}

#[test]
fn the_rule_codes_match_what_protocol_v1_enforces() {
    // Static membership and round robin are not descriptions the encoder
    // chose: protocol v1 refuses the alternatives.
    let mut g = full_genesis();
    g.params.staking = Some(StakingParams {
        epoch_length: 10,
        ..StakingParams::default()
    });
    assert!(sumchain_consensus::poa::check_protocol_v1(&g).is_err());
    g.params.staking = Some(StakingParams {
        stake_weighted_selection: true,
        ..StakingParams::default()
    });
    assert!(sumchain_consensus::poa::check_protocol_v1(&g).is_err());
    assert!(sumchain_consensus::poa::check_protocol_v1(&full_genesis()).is_ok());
}

// ── what the commitment covers ──────────────────────────────────────────────

/// Every committed genesis parameter, gate and group value moves the
/// commitment, and the diff names exactly that field.
#[test]
fn every_committed_genesis_field_changes_the_commitment_and_only_its_own_diff() {
    let base = full_genesis();
    let base_c = commitment(&base);
    let mut checked = 0;
    for spec in SCHEMA_V1_FIELDS {
        let genesis_driven = (0x0100..0x0200).contains(&spec.id)
            || ((0x0300..0x0800).contains(&spec.id) && !spec.name.ends_with("_configured"))
            || (0x1000..0x2000).contains(&spec.id);
        if !genesis_driven {
            continue;
        }
        let g = moved(&base, spec.name);
        assert_ne!(
            commitment(&g),
            base_c,
            "{} did not move the commitment",
            spec.name
        );
        assert_eq!(changed_ids(&base, &g), vec![spec.id], "{}", spec.name);
        checked += 1;
    }
    // 21 scalars, 38 group values, 63 activation heights.
    assert_eq!(checked, 122, "fields exercised");
}

#[test]
fn each_group_commits_whether_it_was_configured() {
    let base = full_genesis();
    for (flag, clear) in [
        (
            "staking_configured",
            (|p: &mut ChainParams| p.staking = None) as fn(&mut ChainParams),
        ),
        ("messaging_configured", |p| p.messaging = None),
        ("docclass_configured", |p| p.docclass = None),
        ("governance_configured", |p| p.governance = None),
        ("beacon_params_configured", |p| p.beacon_params = None),
        ("beacon_schedule_configured", |p| p.beacon_schedule = None),
    ] {
        let mut g = base.clone();
        clear(&mut g.params);
        let ids = changed_ids(&base, &g);
        assert!(ids.contains(&id_of(flag)), "{flag} not committed");
    }
    // Staking and messaging fall back to the executor's defaults, which the
    // full genesis already uses, so only the flag moves (apart from the
    // messaging admin, which has no default).
    let mut g = base.clone();
    g.params.staking = None;
    assert_eq!(changed_ids(&base, &g), vec![id_of("staking_configured")]);
}

#[test]
fn chain_identity_is_committed() {
    let base = full_genesis();
    let mut g = base.clone();
    g.chain_id += 1;
    assert!(changed_ids(&base, &g).contains(&id_of("chain_id")));
    let mut g = base.clone();
    g.genesis_time += 1;
    assert!(changed_ids(&base, &g).contains(&id_of("genesis_time")));
    let mut g = base.clone();
    g.alloc.insert(address(5).to_base58(), 1);
    let ids = changed_ids(&base, &g);
    assert!(ids.contains(&id_of("alloc_digest")));
    assert!(ids.contains(&id_of("genesis_block_hash")));
}

#[test]
fn excluded_parameters_do_not_change_the_commitment() {
    let base = full_genesis();
    let base_c = commitment(&base);
    for (name, why) in EXCLUDED_PARAMETERS {
        let g = moved(&base, name);
        assert_eq!(
            commitment(&g),
            base_c,
            "{name} moved the commitment ({why})"
        );
    }
}

#[test]
fn validator_order_changes_the_commitment() {
    let base = full_genesis();
    let mut g = base.clone();
    g.validators.reverse();
    assert_ne!(commitment(&g), commitment(&base));
    assert!(changed_ids(&base, &g).contains(&id_of("validators")));
}

#[test]
fn allocation_input_order_and_spelling_do_not_change_the_commitment() {
    let base = full_genesis();
    let entries: Vec<(String, u128)> = base.alloc.clone().into_iter().collect();
    for rotation in 0..entries.len() {
        let mut rotated = entries.clone();
        rotated.rotate_left(rotation);
        let mut alloc = HashMap::new();
        for (k, v) in rotated {
            alloc.insert(k, v);
        }
        let mut g = base.clone();
        g.alloc = alloc;
        assert_eq!(commitment(&g), commitment(&base));
    }
    // The same address written as hex instead of base58 is the same address.
    let mut g = base.clone();
    let balance = g.alloc.remove(&address(1).to_base58()).unwrap();
    g.alloc.insert(hex::encode(address(1).as_bytes()), balance);
    assert_eq!(commitment(&g), commitment(&base));
}

#[test]
fn an_unparseable_admin_is_committed_as_no_admin() {
    // Execution ignores an admin it cannot parse, so it is no admin.
    let base = full_genesis();
    let mut a = base.clone();
    a.params.messaging.as_mut().unwrap().registry_admin = None;
    let mut b = base.clone();
    b.params.messaging.as_mut().unwrap().registry_admin = Some("not-an-address".into());
    assert_eq!(commitment(&a), commitment(&b));
}

// ── strict encoding ─────────────────────────────────────────────────────────

fn encoding() -> Vec<u8> {
    ccfg::build(&full_genesis()).unwrap().encode()
}

/// Byte offset of the first field (after magic, schema, count).
const FIRST_FIELD: usize = 7 + 2 + 2;

fn malformed(bytes: &[u8]) -> bool {
    matches!(
        ConsensusConfig::decode(bytes),
        Err(ConfigError::Malformed(_)) | Err(ConfigError::UnknownSchema(_))
    )
}

#[test]
fn decoding_round_trips_exactly() {
    let bytes = encoding();
    let decoded = ConsensusConfig::decode(&bytes).expect("decodes");
    assert_eq!(decoded.encode(), bytes);
    assert_eq!(decoded, ccfg::build(&full_genesis()).unwrap());
    assert_eq!(&bytes[..7], MAGIC);
    assert_eq!(
        u16::from_le_bytes([bytes[7], bytes[8]]),
        2,
        "this binary writes schema 2"
    );

    // Every schema-2 field set, and the frozen schema-1 encoding.
    for bytes in [
        full_schema_2_config().encode(),
        ccfg::build_with(&full_genesis(), &SCHEMA_2_DRAFT)
            .unwrap()
            .encode(),
    ] {
        let decoded = ConsensusConfig::decode(&bytes).expect("decodes");
        assert_eq!(decoded.encode(), bytes);
    }
}

#[test]
fn decoding_refuses_anything_the_encoder_would_not_produce() {
    let bytes = encoding();

    let mut b = bytes.clone();
    b[0] ^= 1;
    assert!(malformed(&b), "wrong magic");

    let mut b = bytes.clone();
    b[7] = 3;
    assert_eq!(
        ConsensusConfig::decode(&b),
        Err(ConfigError::UnknownSchema(3))
    );

    // Schema 1's number on schema 2's fields.
    let mut b = bytes.clone();
    b[7] = 1;
    assert!(malformed(&b), "schema-2 fields under schema 1");

    let mut b = bytes.clone();
    b.push(0);
    assert!(malformed(&b), "trailing byte");

    assert!(malformed(&bytes[..bytes.len() - 1]), "truncated");
    assert!(malformed(&bytes[..5]), "shorter than the header");

    // First field is chain_id (id 1, tag 1, len 8). Move its id.
    let mut b = bytes.clone();
    b[FIRST_FIELD] = 0x02;
    assert!(malformed(&b), "duplicate / reordered id");

    let mut b = bytes.clone();
    b[FIRST_FIELD..FIRST_FIELD + 2].copy_from_slice(&0x7fffu16.to_le_bytes());
    assert!(malformed(&b), "unknown id");

    let mut b = bytes.clone();
    b[FIRST_FIELD + 2] = 6;
    assert!(malformed(&b), "wrong tag for the id");

    let mut b = bytes.clone();
    b[FIRST_FIELD + 2] = 0;
    assert!(malformed(&b), "absent tag on a required field");

    let mut b = bytes.clone();
    b[FIRST_FIELD + 3..FIRST_FIELD + 7].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(malformed(&b), "oversized length");

    // Field count one short of the registry.
    let mut b = bytes.clone();
    let n = u16::from_le_bytes([b[9], b[10]]);
    b[9..11].copy_from_slice(&(n - 1).to_le_bytes());
    assert!(malformed(&b), "missing field");
}

#[test]
fn decoding_refuses_a_non_canonical_boolean_and_a_repeated_validator() {
    let c = ccfg::build(&full_genesis()).unwrap();
    let bytes = c.encode();
    // Find staking_configured (a bool) by walking the fields.
    let target = id_of("staking_configured");
    let mut pos = FIRST_FIELD;
    loop {
        let id = u16::from_le_bytes([bytes[pos], bytes[pos + 1]]);
        let len = u32::from_le_bytes(bytes[pos + 3..pos + 7].try_into().unwrap()) as usize;
        if id == target {
            let mut b = bytes.clone();
            b[pos + 7] = 2;
            assert!(malformed(&b), "boolean 2 accepted");
            break;
        }
        pos += 7 + len;
    }

    let mut g = full_genesis();
    let first = g.validators[0].clone();
    g.validators[1] = first;
    assert!(
        ccfg::build(&g).is_err(),
        "a repeated validator must not encode"
    );
}

#[test]
fn every_field_value_is_bound_by_the_commitment() {
    // Codec-level: changing ANY field to another value of its type changes the
    // commitment. Covers fields the genesis cannot move — rule codes and
    // compiled constants.
    let c = ccfg::build(&full_genesis()).unwrap();
    let base = c.commitment();
    let bytes = c.encode();
    let mut pos = FIRST_FIELD;
    let mut seen = 0;
    while pos < bytes.len() {
        let len = u32::from_le_bytes(bytes[pos + 3..pos + 7].try_into().unwrap()) as usize;
        if len > 0 {
            let mut b = bytes.clone();
            b[pos + 7 + len - 1] ^= 0x01;
            assert_ne!(commitment_of(&b), base);
        }
        pos += 7 + len;
        seen += 1;
    }
    assert_eq!(seen, SCHEMA_2.specs().len());
}

/// [`every_field_value_is_bound_by_the_commitment`] over the fields schema 2
/// adds, each set.
#[test]
fn every_schema_2_field_value_is_bound_by_the_commitment() {
    let c = full_schema_2_config();
    let base = c.commitment();
    let bytes = c.encode();
    let added: Vec<u16> = SCHEMA_2.added.iter().map(|a| a.spec.id).collect();
    let mut pos = FIRST_FIELD;
    let mut flipped = Vec::new();
    while pos < bytes.len() {
        let id = u16::from_le_bytes([bytes[pos], bytes[pos + 1]]);
        let len = u32::from_le_bytes(bytes[pos + 3..pos + 7].try_into().unwrap()) as usize;
        if added.contains(&id) {
            assert!(len > 0, "{id:#06x} is set");
            let mut b = bytes.clone();
            b[pos + 7 + len - 1] ^= 0x01;
            assert_ne!(commitment_of(&b), base);
            flipped.push(id);
        }
        pos += 7 + len;
    }
    flipped.sort();
    let mut expected = added;
    expected.sort();
    assert_eq!(flipped, expected);
}

/// The synthetic vector. Computed identically on every architecture CI runs;
/// a change here is a change to schema 1, which is frozen.
#[test]
fn synthetic_golden_vector() {
    let c = ccfg::build_with(&full_genesis(), &SCHEMA_2_DRAFT).unwrap();
    let bytes = c.encode();
    let enc_digest = Hash::hash(&bytes).to_string();
    let commitment = c.commitment().to_string();
    assert_eq!(
        (bytes.len(), enc_digest.as_str(), commitment.as_str()),
        (GOLDEN_LEN, GOLDEN_ENCODING_DIGEST, GOLDEN_COMMITMENT),
    );
}

const GOLDEN_LEN: usize = 7883;
const GOLDEN_ENCODING_DIGEST: &str =
    "0xf9a1ea00dfc23a6bc845f78e335cebd824ee63fd3dadd43b5f9e609a82f3eda8";
const GOLDEN_COMMITMENT: &str =
    "0xab489a8d36f1084fd33077b14bc6ab915a909222f02e5caa37c225f2d9607641";

/// The schema-2 vectors: the same genesis with every schema-2 field absent, and
/// with every one set (the metering identity and schedule from TEST_ONLY
/// stand-ins, [`METERED_STAND_IN`]). Computed identically on every architecture
/// CI runs; a change here is a change to schema 2, which is frozen.
#[test]
fn schema_2_golden_vectors() {
    let vector = |c: ConsensusConfig| {
        let bytes = c.encode();
        (
            bytes.len(),
            Hash::hash(&bytes).to_string(),
            c.commitment().to_string(),
        )
    };
    let dormant = vector(ccfg::build(&full_genesis()).unwrap());
    let set = vector(full_schema_2_config());
    assert_eq!(
        (dormant.0, dormant.1.as_str(), dormant.2.as_str()),
        (GOLDEN_2_LEN, GOLDEN_2_ENCODING_DIGEST, GOLDEN_2_COMMITMENT),
    );
    assert_eq!(
        (set.0, set.1.as_str(), set.2.as_str()),
        (
            GOLDEN_2_SET_LEN,
            GOLDEN_2_SET_ENCODING_DIGEST,
            GOLDEN_2_SET_COMMITMENT
        ),
    );
}

const GOLDEN_2_LEN: usize = 7953;
const GOLDEN_2_ENCODING_DIGEST: &str =
    "0x31d5fd6d76d6f8203154b398491560d375be6071315c8fa2a4ad7e2cb7e16f84";
const GOLDEN_2_COMMITMENT: &str =
    "0x1d33c8889ecad7eb2faed1a95c695897cf8ae77b97966c0ff9f8d63f35653d9f";
const GOLDEN_2_SET_LEN: usize = 8385;
const GOLDEN_2_SET_ENCODING_DIGEST: &str =
    "0xe2b8aad193b0da5871f4f408d4a6c1dfa2fe047cd9b510c639a845e10b6a7522";
const GOLDEN_2_SET_COMMITMENT: &str =
    "0x81d2b42c159ee616f71bdb15509c33319c322fdf1581d78b8d7eb8714b27c67f";

/// Schema 2 is schema 1 plus absent fields: under schema 2, a genesis that sets
/// none of them carries every schema-1 field exactly as schema 1 encodes it,
/// and each added field as absent.
#[test]
fn the_schema_2_encoding_is_the_schema_1_encoding_plus_absent_fields() {
    let one = ccfg::build_with(&full_genesis(), &SCHEMA_2_DRAFT).unwrap();
    let two = ccfg::build(&full_genesis()).unwrap();
    assert_eq!(one.schema().number, 1);
    assert_eq!(two.schema().number, 2);
    assert_eq!(
        two.fields().len(),
        one.fields().len() + SCHEMA_2.added.len()
    );
    for f in two.fields() {
        match one.fields().iter().find(|o| o.id == f.id) {
            Some(o) => assert_eq!(o, f),
            None => {
                assert!(
                    SCHEMA_2.added.iter().any(|a| a.spec.id == f.id),
                    "{:#06x}",
                    f.id
                );
                assert_eq!(f.value, Value::Absent, "{:#06x}", f.id);
            }
        }
    }
    assert_eq!(one.extend_to(&SCHEMA_2).unwrap(), two);
}

// ── the local baseline ──────────────────────────────────────────────────────

#[test]
fn a_fresh_database_records_an_unverified_local_baseline() {
    let dir = TempDir::new().unwrap();
    let db = open(&dir);
    let g = full_genesis();
    let out = ccfg::check_at_startup(&db, &g, 0).unwrap();
    assert_eq!(
        out,
        StartupOutcome::Initialized {
            commitment: commitment(&g),
            baseline_height: 0
        }
    );
    let r = ccfg::read_record(&db).unwrap().expect("recorded");
    assert_eq!(r.status, BaselineStatus::UnverifiedLocalBaseline);
    assert_eq!(r.status.label(), "unverified-local-baseline");
    assert_eq!(r.commitment, commitment(&g));
    assert_eq!(r.initial_commitment, r.commitment);
    assert_eq!(r.transition_count, 0);
    assert_eq!(
        ccfg::check_at_startup(&db, &g, 0).unwrap(),
        StartupOutcome::Unchanged {
            commitment: commitment(&g)
        }
    );
}

#[test]
fn an_existing_database_without_a_baseline_initializes_at_its_head() {
    let dir = TempDir::new().unwrap();
    let db = open(&dir);
    let g = full_genesis();
    let out = ccfg::check_at_startup(&db, &g, 12_345).unwrap();
    assert!(matches!(
        out,
        StartupOutcome::Initialized {
            baseline_height: 12_345,
            ..
        }
    ));
    assert_eq!(
        ccfg::read_record(&db).unwrap().unwrap().baseline_height,
        12_345
    );
}

#[test]
fn a_baseline_that_cannot_be_written_refuses_startup() {
    let dir = TempDir::new().unwrap();
    drop(open(&dir)); // create it
    let ro = Database::open_read_only(dir.path()).unwrap();
    let err = ccfg::check_at_startup(&ro, &full_genesis(), 0).unwrap_err();
    assert!(matches!(err, ConfigError::Storage(_)), "{err}");
    assert!(err.to_string().contains("refusing to start"), "{err}");
}

fn tamper(db: &Database, key: &[u8], f: impl FnOnce(&mut Vec<u8>)) {
    let mut raw = db.get(cf::META, key).unwrap().unwrap();
    f(&mut raw);
    db.put(cf::META, key, &raw).unwrap();
}

type Damage = Box<dyn Fn(&mut Vec<u8>)>;

#[test]
fn a_damaged_baseline_is_refused_and_never_recreated() {
    let g = full_genesis();
    let cases: Vec<(&str, Damage)> = vec![
        (
            "flipped encoding byte",
            Box::new(|r| *r.last_mut().unwrap() ^= 1),
        ),
        ("flipped commitment byte", Box::new(|r| r[60] ^= 1)),
        ("truncated", Box::new(|r| r.truncate(r.len() - 3))),
        ("trailing byte", Box::new(|r| r.push(0))),
        ("unknown record version", Box::new(|r| r[0] = 9)),
        ("unknown status", Box::new(|r| r[2] = 9)),
        ("claims a transition", Box::new(|r| r[43] = 1)),
        // Record header is 87 bytes; the encoding's schema follows its magic.
        ("schema from a newer binary", Box::new(|r| r[87 + 7] = 3)),
    ];
    for (what, damage) in cases {
        let dir = TempDir::new().unwrap();
        let db = open(&dir);
        ccfg::check_at_startup(&db, &g, 0).unwrap();
        tamper(&db, RECORD_KEY, |r| damage(r));
        let damaged = db.get(cf::META, RECORD_KEY).unwrap();
        let err = ccfg::check_at_startup(&db, &g, 0).unwrap_err();
        assert!(
            matches!(err, ConfigError::RecordCorrupt(_)),
            "{what}: {err}"
        );
        if what.starts_with("schema") {
            assert!(err.to_string().contains("newer binary"), "{err}");
        }
        assert_eq!(
            db.get(cf::META, RECORD_KEY).unwrap(),
            damaged,
            "{what}: rewritten"
        );
    }
}

#[test]
fn a_non_gate_change_is_refused_with_a_field_level_diff() {
    let dir = TempDir::new().unwrap();
    let db = open(&dir);
    let g = full_genesis();
    ccfg::check_at_startup(&db, &g, 50).unwrap();
    let before = db.get(cf::META, RECORD_KEY).unwrap();

    let mut changed = g.clone();
    changed.params.min_fee += 1;
    let err = ccfg::check_at_startup(&db, &changed, 50).unwrap_err();
    let msg = err.to_string();
    assert!(matches!(err, ConfigError::Refused(_)), "{msg}");
    assert!(msg.contains("min_fee (0x0102)"), "{msg}");
    assert!(msg.contains(&commitment(&g).to_string()), "{msg}");
    assert!(msg.contains(&commitment(&changed).to_string()), "{msg}");
    assert!(msg.contains("acknowledge-consensus-config"), "{msg}");
    assert_eq!(
        db.get(cf::META, RECORD_KEY).unwrap(),
        before,
        "record moved"
    );
}

#[test]
fn a_future_gate_reschedule_is_recorded_as_a_transition() {
    let dir = TempDir::new().unwrap();
    let db = open(&dir);
    let g = full_genesis();
    ccfg::check_at_startup(&db, &g, 10).unwrap();

    let mut later = g.clone();
    later.params.nft_receipt_failure_enabled_from_height = Some(100);
    match ccfg::check_at_startup(&db, &later, 10).unwrap() {
        StartupOutcome::GatesRescheduled { from, to, changes } => {
            assert_eq!(from, commitment(&g));
            assert_eq!(to, commitment(&later));
            assert_eq!(changes.len(), 1);
            assert_eq!(changes[0].name, "nft_receipt_failure_enabled_from_height");
        }
        other => panic!("{other:?}"),
    }
    let history = ccfg::read_transitions(&db).unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].kind, TransitionKind::GateReschedule);
    assert_eq!(history[0].at_height, 10);
    assert_eq!(commitment_of(&history[0].old_encoding), commitment(&g));
    assert_eq!(
        ccfg::check_at_startup(&db, &later, 10).unwrap(),
        StartupOutcome::Unchanged {
            commitment: commitment(&later)
        }
    );
}

#[test]
fn a_change_to_a_gate_the_chain_has_passed_is_refused() {
    let dir = TempDir::new().unwrap();
    let db = open(&dir);
    let mut g = full_genesis();
    g.params.nft_receipt_failure_enabled_from_height = Some(5);
    ccfg::check_at_startup(&db, &g, 10).unwrap();

    let mut moved_gate = g.clone();
    moved_gate.params.nft_receipt_failure_enabled_from_height = Some(6);
    let err = ccfg::check_at_startup(&db, &moved_gate, 10).unwrap_err();
    assert!(err.to_string().contains("already passed"), "{err}");

    // And no acknowledgement can permit it.
    let err = ccfg::acknowledge(
        &db,
        &moved_gate,
        10,
        commitment(&g),
        commitment(&moved_gate),
    )
    .unwrap_err();
    assert!(err.to_string().contains("already passed"), "{err}");
    assert!(ccfg::read_transitions(&db).unwrap().is_empty());
}

#[test]
fn a_stopped_node_acknowledgement_records_the_change() {
    let dir = TempDir::new().unwrap();
    let db = open(&dir);
    let g = full_genesis();
    ccfg::check_at_startup(&db, &g, 20).unwrap();
    let mut changed = g.clone();
    changed.params.max_contract_gas += 1;

    let done = ccfg::acknowledge(&db, &changed, 20, commitment(&g), commitment(&changed)).unwrap();
    assert_eq!(done.seq, 1);
    assert_eq!(done.changes.len(), 1);
    assert_eq!(done.changes[0].name, "max_contract_gas");

    let r = ccfg::read_record(&db).unwrap().unwrap();
    assert_eq!(r.commitment, commitment(&changed));
    assert_eq!(r.initial_commitment, commitment(&g));
    assert_eq!(r.baseline_height, 20);
    let history = ccfg::read_transitions(&db).unwrap();
    assert_eq!(history[0].kind, TransitionKind::OperatorAcknowledged);
    assert_eq!(history[0].changed_ids, vec![id_of("max_contract_gas")]);
    assert_eq!(
        ccfg::check_at_startup(&db, &changed, 20).unwrap(),
        StartupOutcome::Unchanged {
            commitment: commitment(&changed)
        }
    );
}

#[test]
fn an_acknowledgement_must_name_both_commitments_exactly() {
    let dir = TempDir::new().unwrap();
    let db = open(&dir);
    let g = full_genesis();
    ccfg::check_at_startup(&db, &g, 0).unwrap();
    let mut changed = g.clone();
    changed.params.max_contract_gas += 1;
    let wrong = Hash::hash(b"wrong");

    for (old, new, why) in [
        (wrong, commitment(&changed), "--old"),
        (commitment(&g), wrong, "--new"),
        (commitment(&g), commitment(&g), "--new"),
    ] {
        let err = ccfg::acknowledge(&db, &changed, 0, old, new).unwrap_err();
        assert!(err.to_string().contains(why), "{err}");
    }
    // Nothing to acknowledge when the configuration did not change.
    let err = ccfg::acknowledge(&db, &g, 0, commitment(&g), commitment(&g)).unwrap_err();
    assert!(err.to_string().contains("nothing to acknowledge"), "{err}");
    assert!(ccfg::read_transitions(&db).unwrap().is_empty());
}

#[test]
fn an_acknowledgement_cannot_change_identity_or_rules_or_create_a_baseline() {
    let dir = TempDir::new().unwrap();
    let db = open(&dir);
    let g = full_genesis();
    let err = ccfg::acknowledge(&db, &g, 0, commitment(&g), commitment(&g)).unwrap_err();
    assert!(
        err.to_string()
            .contains("no consensus configuration baseline"),
        "{err}"
    );

    ccfg::check_at_startup(&db, &g, 0).unwrap();
    let mut other_chain = g.clone();
    other_chain.genesis_time += 1;
    let err = ccfg::acknowledge(
        &db,
        &other_chain,
        0,
        commitment(&g),
        commitment(&other_chain),
    )
    .unwrap_err();
    assert!(err.to_string().contains("chain identity"), "{err}");
    assert!(ccfg::read_transitions(&db).unwrap().is_empty());
}

#[test]
fn the_acknowledgement_needs_the_exclusive_database_lock() {
    let dir = TempDir::new().unwrap();
    let running = open(&dir);
    ccfg::check_at_startup(&running, &full_genesis(), 0).unwrap();
    // A second open of the same directory — what the command does while a
    // node holds it — is refused by RocksDB's lock.
    assert!(Database::open_default(dir.path()).is_err());
    drop(running);
    assert!(Database::open_default(dir.path()).is_ok());
}

#[test]
fn the_transition_history_is_verified_on_every_read() {
    let dir = TempDir::new().unwrap();
    let db = open(&dir);
    let g = full_genesis();
    ccfg::check_at_startup(&db, &g, 0).unwrap();
    let mut a = g.clone();
    a.params.max_contract_gas += 1;
    ccfg::acknowledge(&db, &a, 0, commitment(&g), commitment(&a)).unwrap();
    let mut b = a.clone();
    b.params.nft_receipt_failure_enabled_from_height = Some(900);
    ccfg::check_at_startup(&db, &b, 0).unwrap();
    let history = ccfg::read_transitions(&db).unwrap();
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].new_commitment, history[1].old_commitment);

    let key = |seq: u64| {
        let mut k = TRANSITION_PREFIX.to_vec();
        k.extend_from_slice(&seq.to_be_bytes());
        k
    };

    // Erasing one entry is detected.
    let dir2 = TempDir::new().unwrap();
    let db2 = open(&dir2);
    for (k, v) in db
        .prefix_iter_checked(cf::META, b"consensus_config/")
        .unwrap()
        .map(Result::unwrap)
    {
        db2.put(cf::META, &k, &v).unwrap();
    }
    db2.delete(cf::META, &key(1)).unwrap();
    assert!(matches!(
        ccfg::check_at_startup(&db2, &b, 0),
        Err(ConfigError::RecordCorrupt(_))
    ));

    // An unaccounted extra entry is detected.
    db.put(cf::META, &key(3), b"x").unwrap();
    assert!(matches!(
        ccfg::check_at_startup(&db, &b, 0),
        Err(ConfigError::RecordCorrupt(_))
    ));
    db.delete(cf::META, &key(3)).unwrap();

    // A rewritten entry that breaks the chain is detected.
    tamper(&db, &key(2), |t| t[20] ^= 1);
    assert!(matches!(
        ccfg::check_at_startup(&db, &b, 0),
        Err(ConfigError::RecordCorrupt(_))
    ));
}

#[test]
fn decoding_refuses_a_validator_list_that_repeats_a_key() {
    // Genesis construction already refuses a repeated validator; the codec must
    // refuse it on its own, for a record that never went through a genesis.
    let bytes = encoding();
    let target = id_of("validators");
    let mut pos = FIRST_FIELD;
    loop {
        let id = u16::from_le_bytes([bytes[pos], bytes[pos + 1]]);
        let len = u32::from_le_bytes(bytes[pos + 3..pos + 7].try_into().unwrap()) as usize;
        if id == target {
            // value = count:u32 ‖ (len:u32 ‖ key[32])*; copy key 0 over key 1.
            let v = pos + 7;
            let first = v + 4 + 4;
            let second = first + 32 + 4;
            let mut b = bytes.clone();
            let key: Vec<u8> = b[first..first + 32].to_vec();
            b[second..second + 32].copy_from_slice(&key);
            assert!(malformed(&b), "a repeated validator decoded");
            break;
        }
        pos += 7 + len;
    }
}

#[test]
fn a_history_entry_the_record_does_not_count_is_refused() {
    // A no-op entry (old = new = the current commitment) appended past the
    // recorded count keeps the chain intact; only the count can catch it.
    let dir = TempDir::new().unwrap();
    let db = open(&dir);
    let g = full_genesis();
    ccfg::check_at_startup(&db, &g, 0).unwrap();
    let c = commitment(&g);
    let enc = ccfg::build(&g).unwrap().encode();
    let mut t = Vec::new();
    t.extend_from_slice(&1u16.to_le_bytes());
    t.extend_from_slice(&1u64.to_le_bytes());
    t.push(2);
    t.extend_from_slice(&0u64.to_le_bytes());
    t.extend_from_slice(c.as_bytes());
    t.extend_from_slice(c.as_bytes());
    t.extend_from_slice(&0u16.to_le_bytes());
    t.extend_from_slice(&(enc.len() as u32).to_le_bytes());
    t.extend_from_slice(&enc);
    let mut key = TRANSITION_PREFIX.to_vec();
    key.extend_from_slice(&1u64.to_be_bytes());
    db.put(cf::META, &key, &t).unwrap();
    assert!(matches!(
        ccfg::check_at_startup(&db, &g, 0),
        Err(ConfigError::RecordCorrupt(_))
    ));
}

/// A schema-2 gate (#277 0x103f, #279 0x1042, #278 0x1040): dormant, it is
/// committed absent; set, schema 2 commits its height. A binary that records
/// schema 1 still refuses it, because schema 1 cannot express it.
fn a_schema_2_gate_is_committed_by_schema_2_and_refused_by_schema_1(
    name: &str,
    id: u16,
    set: fn(&mut Genesis),
) {
    assert_eq!(ccfg::fields::gate_id(name), Some(id));
    assert!(SCHEMA_2
        .added
        .iter()
        .any(|a| a.spec.id == id && a.spec.name == name));
    let base = full_genesis();
    assert_eq!(
        ccfg::build(&base).unwrap().get(id),
        Some(&Value::Absent),
        "the golden fixture holds {name} dormant"
    );

    let mut g = full_genesis();
    set(&mut g);
    let c = ccfg::build(&g).expect("schema 2 commits the gate");
    assert_eq!(c.get(id), Some(&Value::U64(10)));
    let changes = ccfg::build(&base).unwrap().diff(&c).unwrap();
    assert!(
        changes.iter().any(|ch| ch.id == id),
        "{name} moved the commitment"
    );

    let err =
        ccfg::build_with(&g, &SCHEMA_2_DRAFT).expect_err("schema 1 cannot commit to this gate");
    assert!(matches!(err, ConfigError::Refused(_)), "{err}");
    assert!(err.to_string().contains(name), "{err}");
}

#[test]
fn the_credential_schema_gate_is_a_schema_2_field() {
    a_schema_2_gate_is_committed_by_schema_2_and_refused_by_schema_1(
        "credential_schema_validation_enabled_from_height",
        0x103f,
        |g| g.params.credential_schema_validation_enabled_from_height = Some(10),
    );
}

#[test]
fn the_contract_error_rollback_gate_is_a_schema_2_field() {
    a_schema_2_gate_is_committed_by_schema_2_and_refused_by_schema_1(
        "contract_error_rollback_enabled_from_height",
        0x1042,
        |g| g.params.contract_error_rollback_enabled_from_height = Some(10),
    );
}

/// The #278 gate, and the constant its rule reads: the constant is committed
/// exactly while the gate is set, so a schema-1 record carried into schema 2
/// (every added field absent) stays exact.
#[test]
fn the_messaging_timestamp_units_gate_is_a_schema_2_field_with_its_constant() {
    a_schema_2_gate_is_committed_by_schema_2_and_refused_by_schema_1(
        "messaging_timestamp_units_enabled_from_height",
        0x1040,
        |g| g.params.messaging_timestamp_units_enabled_from_height = Some(10),
    );
    let constant = ccfg::schema::MESSAGING_TIMESTAMP_MS_PER_SECOND_ID;
    assert_eq!(constant, 0x252a);
    assert_eq!(
        ccfg::build(&full_genesis()).unwrap().get(constant),
        Some(&Value::Absent)
    );
    let mut g = full_genesis();
    g.params.messaging_timestamp_units_enabled_from_height = Some(10);
    assert_eq!(
        ccfg::build(&g).unwrap().get(constant),
        Some(&Value::U128(
            sumchain_state::messaging_executor::MESSAGING_TIMESTAMP_MS_PER_SECOND as u128
        ))
    );
}
