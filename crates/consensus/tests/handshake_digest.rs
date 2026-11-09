//! The handshake digest (#350): the protocol digest and the running
//! consensus-configuration commitment, folded into the one value a node
//! declares to its peers.
//!
//! What a peer comparison relies on, in order:
//!
//! * the preimage is the domain, the protocol digest and the running
//!   commitment, 91 bytes, in that order;
//! * it moves for every range of the configuration the protocol digest does
//!   not cover, and whenever the protocol digest moves;
//! * it does not depend on what a database recorded or in which schema, so
//!   two nodes running the same rules declare the same value, across restarts;
//! * it ignores the parameters the configuration excludes;
//! * it is never a protocol digest, so a node declaring one and a node
//!   declaring the other never agree.

use std::collections::HashMap;

use sumchain_consensus::consensus_config::{
    self as ccfg,
    record::{acknowledge_schema_transition_with, pending_schema_transition_with},
    schema::{
        MESSAGING_TIMESTAMP_MS_PER_SECOND_ID, SCHEMA_2_ADDED, SCHEMA_3_ADDED, SCHEMA_4_ADDED,
    },
    AddedField, ConsensusConfig, Schema, SchemaPolicy, Source, StartupOutcome, Value,
    HANDSHAKE_DIGEST_DOMAIN, SCHEMA_1, SCHEMA_2, SCHEMA_4,
};
use sumchain_crypto::KeyPair;
use sumchain_genesis::{BeaconParamsConfig, ChainParams, Genesis};
use sumchain_primitives::{GovernanceParams, Hash, StakingParams};
use sumchain_state::protocol_digest::{
    consensus_limits, protocol_digest, protocol_digest_with_limits, LimitValue,
    PROTOCOL_DIGEST_DOMAIN,
};
use sumchain_storage::{cf, Database};
use tempfile::TempDir;

// ── fixtures ────────────────────────────────────────────────────────────────

fn key(i: u8) -> KeyPair {
    KeyPair::from_bytes([i; 32])
}

/// The fixed genesis of the golden vector.
fn golden_genesis() -> Genesis {
    let v = key(31);
    Genesis::new(
        1,
        1_734_624_000_000,
        vec![v.public_key().to_base58()],
        HashMap::from([(v.address().to_base58(), 1_000_000u128)]),
        ChainParams::default(),
    )
}

/// TEST_ONLY compute-pool parameters (no proposed value): every cap `cap`,
/// everything else 0.
fn test_only_compute_pool_params(
    cap: u64,
) -> sumchain_primitives::compute_pool_params::ComputePoolParamsV1 {
    serde_json::from_value(serde_json::json!({
        "b_offer": 0, "b_commit": 0, "b_check": 0,
        "c_layer": 0, "c_tok": 0, "c_sel": 0, "c_emit": 0,
        "accept_reimb": 0, "commit_verify_reimb": 0, "publish_reimb": 0,
        "observe_reimb": 0, "check_reimb": 0, "settle_reimb": 0, "reassign_reimb": 0,
        "max_work_units": cap, "max_generations": 1, "max_reprovisionable_units": 1,
        "max_attempts_per_unit": 1, "max_reassignments_per_file": 1,
        "k_susp": 0, "w_susp": 0, "s_susp": 0, "n_invite_max": 0,
        "max_retention_files_per_job": 1, "max_retention_updates_per_block": 1,
        "max_reverse_index_entries": 1, "output_availability_blocks": 200,
        "d_avail": 0, "d_ack": 0, "d_final": 0
    }))
    .unwrap()
}

/// A genesis in which every group the protocol digest misses is configured,
/// so each of their values can be moved on its own.
fn configured_genesis() -> Genesis {
    let params = ChainParams {
        staking: Some(StakingParams::default()),
        governance: Some(GovernanceParams {
            validator_authority_threshold_bps: 6_000,
            quorum_bps: 3_000,
            pass_threshold_bps: 5_000,
            voting_period_blocks: 1_000,
            max_snapshot_holders: 100,
            proposal_bond: 1_000,
            treasury: None,
            min_koppa_for_eligibility: 10,
        }),
        beacon_params: Some(BeaconParamsConfig {
            f: 1,
            c: 1,
            t: 2,
            q_dkg: 3,
            n: 5,
        }),
        compute_pool_params: Some(test_only_compute_pool_params(1)),
        messaging_timestamp_units_enabled_from_height: Some(20_000),
        ..ChainParams::default()
    };
    let v = key(32);
    Genesis::new(
        7,
        1_700_000_000_000,
        vec![v.public_key().to_base58(), key(33).public_key().to_base58()],
        HashMap::from([(v.address().to_base58(), 1_000u128)]),
        params,
    )
}

fn pd(g: &Genesis) -> Hash {
    protocol_digest(g).expect("protocol digest")
}

fn running(g: &Genesis) -> ConsensusConfig {
    ccfg::build(g).expect("running configuration")
}

fn handshake(g: &Genesis) -> Hash {
    ccfg::handshake_digest_for(g).expect("handshake digest")
}

// ── the value ───────────────────────────────────────────────────────────────

/// The preimage, byte for byte, and one golden vector.
///
/// The vector is this binary's value for [`golden_genesis`]. A change that
/// moves it changes what every node declares to its peers, so it is a
/// same-window change, and the vector is updated in that change, deliberately.
#[test]
fn the_preimage_layout_and_the_golden_vector() {
    let g = golden_genesis();
    let pd1 = pd(&g);
    let c = running(&g);
    assert_eq!(c.schema().number, ccfg::PRODUCTION.writes.number);

    let mut preimage = Vec::new();
    preimage.extend_from_slice(b"sumchain/protocol-digest/v2");
    preimage.extend_from_slice(pd1.as_bytes());
    preimage.extend_from_slice(c.commitment().as_bytes());
    assert_eq!(preimage.len(), 91);
    assert_eq!(&preimage[0..27], HANDSHAKE_DIGEST_DOMAIN);
    assert_eq!(&preimage[27..59], pd1.as_bytes());
    assert_eq!(&preimage[59..91], c.commitment().as_bytes());

    let digest = ccfg::handshake_digest(pd1, &c);
    assert_eq!(digest, Hash::hash(&preimage));
    assert_eq!(handshake(&g), digest);

    assert_eq!(
        (
            pd1.to_string().as_str(),
            c.commitment().to_string().as_str(),
            digest.to_string().as_str(),
        ),
        (
            GOLDEN_PROTOCOL_DIGEST,
            GOLDEN_RUNNING_COMMITMENT,
            GOLDEN_HANDSHAKE_DIGEST
        ),
    );
}

const GOLDEN_PROTOCOL_DIGEST: &str =
    "0xec12eb94a85e3440c93af4086f9d3a1e8883020d507bd95f53068177f0ab9494";
const GOLDEN_RUNNING_COMMITMENT: &str =
    "0xf94779483d7d0299745c1b0124b0f53aaaadf3321ced737572453e6e774e3cf9";
const GOLDEN_HANDSHAKE_DIGEST: &str =
    "0x16a7c914c53c807992efb6b7d2c8626bc6bafc8d4c84ab71b1a472adff02712f";

/// The configuration [`compiled_stand_in`] builds: [`ccfg::PRODUCTION`] with
/// the messaging timestamp unit's source replaced, as a binary compiled with a
/// different value of that constant would compute it.
fn stand_in_timestamp_unit(g: &Genesis) -> Value {
    match g.params.messaging_timestamp_units_enabled_from_height {
        None => Value::Absent,
        Some(_) => Value::U128(
            sumchain_state::messaging_executor::MESSAGING_TIMESTAMP_MS_PER_SECOND as u128 + 1,
        ),
    }
}

const STAND_IN_ADDED: [AddedField; SCHEMA_2_ADDED.len()] = {
    let mut out = [SCHEMA_2_ADDED[0]; SCHEMA_2_ADDED.len()];
    let mut i = 0;
    while i < SCHEMA_2_ADDED.len() {
        out[i] = SCHEMA_2_ADDED[i];
        if out[i].spec.id == MESSAGING_TIMESTAMP_MS_PER_SECOND_ID {
            out[i].source = Source::Param(stand_in_timestamp_unit);
        }
        i += 1;
    }
    out
};

static STAND_IN_SCHEMA_2: Schema = Schema {
    number: 2,
    previous: Some(&SCHEMA_1),
    added: &STAND_IN_ADDED,
};

static STAND_IN_SCHEMA_3: Schema = Schema {
    number: 3,
    previous: Some(&STAND_IN_SCHEMA_2),
    added: SCHEMA_3_ADDED,
};

static STAND_IN_SCHEMA_4: Schema = Schema {
    number: 4,
    previous: Some(&STAND_IN_SCHEMA_3),
    added: SCHEMA_4_ADDED,
};

static COMPILED_STAND_IN: SchemaPolicy = SchemaPolicy {
    reads: &[&SCHEMA_1, &STAND_IN_SCHEMA_2, &STAND_IN_SCHEMA_3],
    writes: &STAND_IN_SCHEMA_3,
    knows: &STAND_IN_SCHEMA_4,
};

/// One value from each range of the configuration that the protocol digest
/// does not cover, and a compiled constant through the `build_with` seam. Each
/// leaves the protocol digest equal and moves the handshake digest.
#[test]
fn it_moves_for_every_range_the_protocol_digest_misses() {
    let base = configured_genesis();
    let base_pd = pd(&base);
    let base_handshake = handshake(&base);

    let mut cases: Vec<(u16, &str, Genesis)> = Vec::new();
    let mut g = base.clone();
    g.params.min_fee += 1;
    cases.push((0x0102, "min_fee", g));
    let mut g = base.clone();
    g.params.finality_depth += 1;
    cases.push((0x0103, "finality_depth", g));
    let mut g = base.clone();
    g.params.staking.as_mut().unwrap().epoch_length += 1;
    cases.push((0x030a, "staking.epoch_length", g));
    let mut g = base.clone();
    g.params
        .governance
        .as_mut()
        .unwrap()
        .validator_authority_threshold_bps += 1;
    cases.push((0x0601, "governance.validator_authority_threshold_bps", g));
    let mut g = base.clone();
    g.params.beacon_params.as_mut().unwrap().f += 1;
    cases.push((0x0701, "beacon_params.f", g));
    let mut g = base.clone();
    g.params.compute_pool_params = Some(test_only_compute_pool_params(2));
    cases.push((0x0720, "compute_pool_params", g));

    for (id, name, g) in &cases {
        assert_eq!(
            running(&base)
                .diff(&running(g))
                .unwrap()
                .iter()
                .map(|c| c.id)
                .collect::<Vec<_>>(),
            vec![*id],
            "{name} moves exactly its own field"
        );
        assert_eq!(pd(g), base_pd, "{name} is outside the protocol digest");
        assert_ne!(
            handshake(g),
            base_handshake,
            "{name} ({id:#06x}) must move the handshake digest"
        );
    }

    // A compiled constant: the same genesis, built by a binary whose messaging
    // timestamp unit differs.
    COMPILED_STAND_IN.check().unwrap();
    let other = ccfg::build_with(&base, &COMPILED_STAND_IN).unwrap();
    let other = ConsensusConfig::decode(&other.encode()).unwrap();
    assert_eq!(
        running(&base)
            .diff(&other)
            .unwrap()
            .iter()
            .map(|c| c.id)
            .collect::<Vec<_>>(),
        vec![MESSAGING_TIMESTAMP_MS_PER_SECOND_ID]
    );
    assert!(
        !consensus_limits()
            .iter()
            .any(|(n, _)| *n == "MESSAGING_TIMESTAMP_MS_PER_SECOND"),
        "the constant is outside the protocol digest"
    );
    assert_ne!(ccfg::handshake_digest(base_pd, &other), base_handshake);
}

/// A gate height, and a compiled limit through `protocol_digest_with_limits`:
/// each moves the protocol digest, and the handshake digest with it.
#[test]
fn it_moves_whenever_the_protocol_digest_moves() {
    let base = configured_genesis();
    let base_handshake = handshake(&base);

    let mut gate = base.clone();
    gate.params.messaging_timestamp_units_enabled_from_height = Some(20_001);
    assert_ne!(pd(&gate), pd(&base));
    assert_ne!(handshake(&gate), base_handshake);

    // The limit alone: the same running configuration, the protocol digest a
    // binary with a doubled block write-set ceiling computes.
    let doubled: Vec<(&'static str, LimitValue)> = consensus_limits()
        .into_iter()
        .map(|(n, v)| match (n, v) {
            ("MAX_BLOCK_WRITE_SET_BYTES", LimitValue::Num(x)) => (n, LimitValue::Num(x * 2)),
            other => other,
        })
        .collect();
    let other_pd = protocol_digest_with_limits(&base, &doubled).unwrap();
    assert_ne!(other_pd, pd(&base));
    assert_ne!(
        ccfg::handshake_digest(other_pd, &running(&base)),
        base_handshake
    );
}

// ── the record does not enter it ────────────────────────────────────────────

/// The release that wrote schema 2.
static SCHEMA_2_RELEASE: SchemaPolicy = SchemaPolicy {
    reads: &[&SCHEMA_1, &SCHEMA_2],
    writes: &SCHEMA_2,
    knows: &SCHEMA_4,
};

/// The genesis `tests/data/consensus_config_schema1_db.tsv` records (as in
/// `consensus_config_schema3.rs`).
fn fixture_genesis() -> Genesis {
    let v = KeyPair::from_bytes([12u8; 32]);
    let mut g = Genesis::new(
        1,
        1_734_624_000_000,
        vec![v.public_key().to_base58()],
        HashMap::from([(v.address().to_base58(), 1_000_000u128)]),
        ChainParams::default(),
    );
    g.params.nft_receipt_failure_enabled_from_height = Some(1_000);
    g.params.max_contract_gas += 1;
    g
}

/// Height of the fixture's last write.
const HEIGHT: u64 = 20;

/// A database holding exactly the schema-1 release's entries.
fn schema_1_database() -> (TempDir, Database) {
    let dir = TempDir::new().unwrap();
    let db = Database::open_default(dir.path()).unwrap();
    let text = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/data/consensus_config_schema1_db.tsv"),
    )
    .unwrap();
    let mut batch = db.batch();
    for line in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
    {
        let (k, v) = line.split_once('\t').expect("key\tvalue");
        batch
            .put(cf::META, &hex::decode(k).unwrap(), &hex::decode(v).unwrap())
            .unwrap();
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
    (dir, db)
}

/// Three databases of one genesis: a fresh schema-3 one; a schema-2 record
/// moved by `acknowledge_schema_transition`; and a schema-2 record left as it
/// is, through a gate reschedule and its restore. Each starts, and records a
/// different commitment or a different history. The handshake digest is the
/// same for all three, because it is the running configuration's.
#[test]
fn it_is_independent_of_the_record_schema_and_history() {
    let g = fixture_genesis();

    let fresh_dir = TempDir::new().unwrap();
    let fresh = Database::open_default(fresh_dir.path()).unwrap();
    assert!(matches!(
        ccfg::check_at_startup(&fresh, &g, HEIGHT).unwrap(),
        StartupOutcome::Initialized { .. }
    ));

    let (_moved_dir, moved) = schema_2_database();
    let p = ccfg::pending_schema_transition(&moved).unwrap().unwrap();
    assert_eq!((p.from_schema, p.to_schema), (2, 3));
    ccfg::acknowledge_schema_transition(&moved, HEIGHT, p.old, p.new).unwrap();
    assert!(matches!(
        ccfg::check_at_startup(&moved, &g, HEIGHT).unwrap(),
        StartupOutcome::Unchanged { .. }
    ));

    let (_kept_dir, kept) = schema_2_database();
    let mut rescheduled = g.clone();
    rescheduled.params.nft_receipt_failure_enabled_from_height = Some(1_001);
    assert!(matches!(
        ccfg::check_at_startup(&kept, &rescheduled, HEIGHT).unwrap(),
        StartupOutcome::GatesRescheduled { .. }
    ));
    assert!(matches!(
        ccfg::check_at_startup(&kept, &g, HEIGHT + 1).unwrap(),
        StartupOutcome::GatesRescheduled { .. }
    ));

    let records: Vec<_> = [&fresh, &moved, &kept]
        .iter()
        .map(|db| ccfg::read_record(db).unwrap().unwrap())
        .collect();
    let schemas: Vec<u16> = records.iter().map(|r| r.config.schema().number).collect();
    assert_eq!(schemas, [3, 3, 2]);
    let histories: Vec<u64> = records.iter().map(|r| r.transition_count).collect();
    assert_eq!(histories[0], 0);
    assert!(histories[1] > 0 && histories[2] > histories[1]);
    // The reason the running configuration is declared and not the record:
    // the recorded commitments differ although the rules are the same.
    assert_ne!(records[0].commitment, records[2].commitment);
    let pd1 = pd(&g);
    assert_ne!(
        ccfg::handshake_digest(pd1, &records[0].config),
        ccfg::handshake_digest(pd1, &records[2].config),
        "a digest of the RECORD would refuse a peer that runs the same rules"
    );

    // What each of the three nodes declares, computed as `Node::new` does
    // after its start succeeded.
    let declared = handshake(&g);
    for (i, record) in records.iter().enumerate() {
        assert_eq!(
            ccfg::handshake_digest(pd1, &running(&g)),
            declared,
            "database {i}"
        );
        assert!(
            record
                .config
                .extend_to(running(&g).schema())
                .map_or(record.config == running(&g), |moved| moved == running(&g)),
            "database {i} records the running rules"
        );
    }
}

/// A restart with the same genesis and binary declares the same value; no
/// database is read to compute it.
#[test]
fn it_is_stable_across_a_restart() {
    let g = fixture_genesis();
    let before = handshake(&g);
    let dir = TempDir::new().unwrap();
    {
        let db = Database::open_default(dir.path()).unwrap();
        ccfg::check_at_startup(&db, &g, 0).unwrap();
    }
    let db = Database::open_default(dir.path()).unwrap();
    assert!(matches!(
        ccfg::check_at_startup(&db, &g, 0).unwrap(),
        StartupOutcome::Unchanged { .. }
    ));
    assert_eq!(handshake(&g), before);
    assert_eq!(handshake(&g.clone()), before);
}

/// A parameter the configuration excludes (`fields::EXCLUDED_PARAMETERS`) is
/// not a rule: it moves neither digest.
#[test]
fn it_ignores_excluded_parameters() {
    let base = configured_genesis();
    let mut g = base.clone();
    g.params.block_time_ms += 1;
    assert_eq!(pd(&g), pd(&base));
    assert_eq!(running(&g).commitment(), running(&base).commitment());
    assert_eq!(handshake(&g), handshake(&base));
}

/// The two domains have the same length and differ, so no handshake preimage
/// is a protocol-digest preimage, and the values never agree.
#[test]
fn it_never_equals_a_protocol_digest() {
    assert_eq!(HANDSHAKE_DIGEST_DOMAIN.len(), PROTOCOL_DIGEST_DOMAIN.len());
    assert_eq!(HANDSHAKE_DIGEST_DOMAIN.len(), 27);
    assert_ne!(HANDSHAKE_DIGEST_DOMAIN, PROTOCOL_DIGEST_DOMAIN);

    let geneses = [golden_genesis(), configured_genesis(), fixture_genesis()];
    let protocol: Vec<Hash> = geneses.iter().map(pd).collect();
    for g in &geneses {
        let h = handshake(g);
        assert!(!protocol.contains(&h));
        assert_ne!(h, running(g).commitment());
    }
}
