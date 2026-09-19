//! The two startup gates, exercised through the REAL boot sequence.
//!
//! `Node::with_rpc_config` is the only place `journal::validate_startup` and
//! `check_activation_parameters` both run, in the order the comments in
//! `node.rs` say they must. Neither is reachable from an integration test —
//! `sumchain-node` has no library target — so these live in the binary crate as
//! a unit-test module, included by `#[path]` so that `node.rs` itself is not
//! turned into a test file.
//!
//! What is driven here, on real databases:
//!
//! * **Restart across an activation boundary.** A validator publishes below a
//!   height at which a gate opens, is stopped, is restarted THROUGH THE REAL
//!   BOOT, and publishes above it. Its state is compared against a node that
//!   followed the same chain without ever stopping. The recorded activation
//!   heights, the journal format watermark and the pinned journal boundary all
//!   live in `cf::META` and all have to come back.
//!
//! * **Downgrade refusal.** A database holding a record format newer than this
//!   binary implements must refuse to START, and must do so whether the evidence
//!   is in the records or only in the stamped watermark — which is the case the
//!   stamped row exists for, because pruning deletes records and does not delete
//!   the row.
//!
//! # What the fixture does NOT do
//!
//! It does not run `Node::run`. That binds an RPC port, a health port and a
//! libp2p listener and starts a block producer, none of which is the subject.
//! Every gate under test runs in `with_rpc_config`, before any of that exists —
//! which is exactly the property `node.rs` claims for them — so construction
//! succeeding or failing IS the gate's verdict.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use sumchain_consensus::{ConsensusEngine, PoAEngine};
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::{ChainParams, Genesis};
use sumchain_primitives::{
    Address, Block, SignedTransaction, Transaction, TransactionV2, TxPayload, TxStatus,
};
use sumchain_state::{Mempool, MempoolConfig, StateManager};
use sumchain_storage::journal::{
    persisted_format_high_water, undo_history_floor, ActivationSource, JournalActivation,
    FORMAT_HIGH_WATER_META_KEY, FORMAT_VERSION_V1,
};
use sumchain_storage::{cf, Database, ReceiptStore};

use super::Node;

const CHAIN_ID: u64 = 1;

/// The height at and above which the SRC-87X authorization rules bind. The gate
/// is chosen because it is CONSENSUS-RELEVANT without needing half a million
/// blocks: it changes which transactions succeed, and the receipt's success bit
/// and fee are folded into the block state root.
const AUTH_BOUNDARY: u64 = 6;

/// The pinned journal boundary. Pinned rather than observed so that it is a
/// chain-defined number every node reads the same way — and so that a restart
/// has something to get wrong.
const JOURNAL_BOUNDARY: u64 = 2;

const PROVIDER_ID: [u8; 32] = [0x68; 32];
const PRESCRIPTION_ID: [u8; 32] = [0x69; 32];
const FEE: u128 = 100;
const HEALTHCARE_FAILED: TxStatus = TxStatus::Failed(14);

// ─────────────────────────────────────────────────────────────────────────────
// Fixture
// ─────────────────────────────────────────────────────────────────────────────

/// A raw consensus stack on a directory: the thing that PRODUCES blocks.
///
/// Deliberately separate from `Node`, which is the thing that BOOTS. A test that
/// only ever used one of them could not tell a restart from a continuation.
struct Producer {
    db: Arc<Database>,
    state: Arc<StateManager>,
    mempool: Arc<Mempool>,
    consensus: Arc<PoAEngine>,
}

impl Producer {
    fn open(dir: &Path, genesis: &Genesis, secret: [u8; 32]) -> Self {
        let db = Arc::new(Database::open_default(dir).expect("open database"));
        let state = Arc::new(StateManager::new(db.clone(), CHAIN_ID));
        let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
        let consensus = Arc::new(
            PoAEngine::new(
                db.clone(),
                state.clone(),
                mempool.clone(),
                genesis,
                Some(KeyPair::from_bytes(secret)),
            )
            .expect("engine"),
        );
        Self {
            db,
            state,
            mempool,
            consensus,
        }
    }

    async fn produce(&self, tx: SignedTransaction) -> Block {
        self.mempool.add(tx).expect("mempool accepts");
        let txs = self.mempool.select_for_block(100);
        assert_eq!(txs.len(), 1, "one transaction per block in this fixture");
        self.consensus
            .propose_block(txs)
            .await
            .expect("propose block")
    }

    /// Every row in every column family the database opens, so that two nodes
    /// can be compared over the WHOLE store rather than over the families
    /// someone remembered to list.
    fn snapshot(&self) -> BTreeMap<(String, Vec<u8>), Vec<u8>> {
        let mut out = BTreeMap::new();
        for family in sumchain_storage::db::ALL_CFS {
            for (k, v) in self.db.iter(family).expect("iterate") {
                out.insert(((*family).to_string(), k.to_vec()), v.to_vec());
            }
        }
        out
    }
}

/// Drop everything holding the RocksDB lock. A "restart" that left a handle
/// alive would be a no-op that passed: RocksDB refuses a directory whose lock is
/// still held, so the reopen below would error rather than silently reuse.
fn close(p: Producer) {
    let Producer {
        db,
        state,
        mempool,
        consensus,
    } = p;
    drop(consensus);
    drop(mempool);
    drop(state);
    drop(db);
}

/// The REAL boot sequence, on an existing directory. `Ok` means every startup
/// gate passed; the `Err` string is the refusal an operator would see.
fn boot(dir: &Path, genesis: &Genesis, secret: Option<[u8; 32]>) -> Result<(), String> {
    let rpc: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let health: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let node = Node::with_rpc_config(
        dir.to_path_buf(),
        genesis.clone(),
        secret.map(KeyPair::from_bytes),
        sumchain_p2p::NetworkConfig::default(),
        rpc,
        health,
        sumchain_rpc::RpcAuthConfig::disabled(),
        sumchain_rpc::RateLimitConfig::disabled(),
        crate::config::ConsensusSettings::default(),
    );
    match node {
        Ok(n) => {
            // Release the database lock before the caller reopens it.
            drop(n);
            Ok(())
        }
        Err(e) => Err(format!("{e:#}")),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Transactions
// ─────────────────────────────────────────────────────────────────────────────

fn healthcare_tx(
    kp: &KeyPair,
    nonce: u64,
    op: sumchain_primitives::healthcare::HealthcareOperation,
    payload: &impl serde::Serialize,
) -> SignedTransaction {
    let t = TransactionV2 {
        chain_id: CHAIN_ID,
        from: kp.address(),
        fee: FEE,
        nonce,
        payload: TxPayload::Healthcare(sumchain_primitives::healthcare::HealthcareTxData {
            operation: op,
            data: bincode::serialize(payload).expect("serialize"),
            recipient: Address::ZERO,
        }),
    };
    let sig = sign(t.signing_hash().as_bytes(), kp.private_key());
    SignedTransaction::new_v2(t, *sig.as_bytes(), *kp.public_key().as_bytes())
}

fn transfer(from: &KeyPair, to: Address, amount: u128, nonce: u64) -> SignedTransaction {
    let tx = Transaction::new(CHAIN_ID, from.address(), to, amount, 10, nonce);
    let sig = sign(tx.signing_hash().as_bytes(), from.private_key());
    SignedTransaction::new(tx, *sig.as_bytes(), *from.public_key().as_bytes())
}

fn provider_profile(issuer: Address) -> sumchain_primitives::healthcare::ProviderProfile {
    use sumchain_primitives::healthcare::*;
    ProviderProfile {
        provider_id: PROVIDER_ID,
        provider_commitment: [0x69; 32],
        provider_type: ProviderType::Hospital,
        jurisdiction_code: "US-CA".to_string(),
        public_reference: None,
        specialties_commitment: None,
        credentials_commitment: None,
        policy_id: [12u8; 32],
        issuer_class: HealthcareIssuerClass::GovernmentHealthAgency,
        issuer_address: issuer,
        status: ProviderStatus::Active,
        created_at: 1_000,
        updated_at: 1_000,
        registered_at_height: 1,
        network_affiliations: vec![],
        attachments: vec![],
    }
}

fn prescription(
    issuer: Address,
    patient: Address,
) -> sumchain_primitives::healthcare::Prescription {
    use sumchain_primitives::agreement::PartyRef;
    use sumchain_primitives::healthcare::*;
    Prescription {
        prescription_id: PRESCRIPTION_ID,
        patient_address: patient,
        prescription_type: PrescriptionType::StandardPrescription,
        prescription_commitment: [0x6A; 32],
        patient_ref: PartyRef::Commitment([0x6B; 32]),
        patient_nullifier: [0x6C; 32],
        prescriber_ref: PartyRef::Commitment([0x6D; 32]),
        prescriber_provider_id: PROVIDER_ID,
        pharmacy_ref: None,
        medication_commitment: [0x6E; 32],
        quantity_commitment: [0x6F; 32],
        days_supply_commitment: None,
        refills_authorized: 200,
        refills_remaining: 200,
        is_controlled: false,
        date_written: 900,
        effective_from: None,
        expiry: 9_000_000,
        issuer_address: issuer,
        issuer_class: HealthcareIssuerClass::MedicalPractice,
        policy_id: [12u8; 32],
        revocation_ref: None,
        status: PrescriptionStatus::Active,
        created_at: 900,
        updated_at: 900,
        recorded_at_height: 1,
        supersedes: None,
        fill_history: vec![],
        attachments: vec![],
    }
}

/// A fill by someone with no relationship to the prescription. Succeeds below
/// `AUTH_BOUNDARY`, refused at and above it. A fresh sender each time, because a
/// refused healthcare transaction does not advance the sender's nonce and the
/// executor requires an exact match.
fn stranger_fill(stranger: &KeyPair, n: u64) -> SignedTransaction {
    #[derive(serde::Serialize)]
    struct Fill {
        prescription_id: [u8; 32],
        fill_commitment: [u8; 32],
    }
    healthcare_tx(
        stranger,
        0,
        sumchain_primitives::healthcare::HealthcareOperation::FillPrescription,
        &Fill {
            prescription_id: PRESCRIPTION_ID,
            fill_commitment: [n as u8; 32],
        },
    )
}

fn genesis_for(validator: &KeyPair, funded: &[&KeyPair], auth_from: Option<u64>) -> Genesis {
    let mut params = ChainParams::with_v2_enabled();
    params.healthcare_authorization_enabled_from_height = auth_from;
    params.application_journal_enabled_from_height = Some(JOURNAL_BOUNDARY);
    params.finality_depth = 1_000_000;
    let mut alloc = std::collections::HashMap::new();
    alloc.insert(validator.address().to_base58(), 100_000_000u128);
    for f in funded {
        alloc.insert(f.address().to_base58(), 100_000_000u128);
    }
    let g = Genesis::new(
        CHAIN_ID,
        0,
        vec![validator.public_key().to_base58()],
        alloc,
        params,
    );
    Genesis::from_json(&g.to_json().expect("serialize")).expect("the gates must load and validate")
}

// ═══════════════════════════════════════════════════════════════════════════
// 3. Restart across the activation boundary
// ═══════════════════════════════════════════════════════════════════════════

/// A node that stops below an activation height and restarts above it reaches
/// the same state as one that never stopped — and everything the restart has to
/// remember is in `cf::META` and still there.
///
/// The control node is not a second producer: block timestamps come from the
/// wall clock, so two producers cannot make byte-identical blocks and comparing
/// them would compare the clock. The control IMPORTS every block the restarting
/// node published, in one uninterrupted session, and executes each one itself.
/// The comparison is then over the WHOLE store, every column family the database
/// opens, which is the part a root cannot absorb: `accept_imported` adopts a
/// mismatching header root at these heights, so equal roots would prove nothing,
/// and equal ROWS prove the restarted node executed correctly.
///
/// The negative controls at the end are what make the restart's boot gate
/// load-bearing rather than decorative.
#[tokio::test]
async fn a_node_restarting_across_an_activation_boundary_reaches_the_same_state() {
    use sumchain_primitives::healthcare::HealthcareOperation;

    let validator = KeyPair::generate();
    let issuer = KeyPair::generate();
    let patient = KeyPair::generate();
    let strangers: Vec<KeyPair> = (0..6).map(|_| KeyPair::generate()).collect();
    let mut funded: Vec<&KeyPair> = vec![&issuer, &patient];
    funded.extend(strangers.iter());
    let genesis = genesis_for(&validator, &funded, Some(AUTH_BOUNDARY));
    let secret = *validator.private_key().as_bytes();

    let dir_r = tempfile::TempDir::new().expect("temp dir");
    let dir_c = tempfile::TempDir::new().expect("temp dir");

    // ── boot 1: an empty database, through the real sequence ────────────────
    //
    // This is where `check_activation_parameters` RECORDS the heights for the
    // first time. It has to happen before any block exists: a first start on a
    // database that already holds blocks is refused for gates this binary
    // introduced, which includes the pinned journal boundary at
    // JOURNAL_BOUNDARY — asserted at the end of this test rather than assumed.
    boot(dir_r.path(), &genesis, Some(secret)).expect("a first boot on an empty database");
    let recorded_after_first_boot = read_recorded_heights_at(dir_r.path());
    assert_eq!(
        recorded_after_first_boot,
        genesis.params.recorded_activation_heights(),
        "the first boot must record exactly the heights it started under"
    );

    // ── below the boundary ──────────────────────────────────────────────────
    let r = Producer::open(dir_r.path(), &genesis, secret);
    r.consensus.init_genesis(&genesis).expect("init genesis");
    let mut published: Vec<Block> = Vec::new();
    published.push(
        r.produce(healthcare_tx(
            &issuer,
            0,
            HealthcareOperation::RegisterProvider,
            &provider_profile(issuer.address()),
        ))
        .await,
    );
    published.push(
        r.produce(healthcare_tx(
            &issuer,
            1,
            HealthcareOperation::IssuePrescription,
            &prescription(issuer.address(), patient.address()),
        ))
        .await,
    );
    let mut fills: Vec<(u64, SignedTransaction)> = Vec::new();
    for (n, s) in strangers.iter().enumerate().take(3) {
        let tx = stranger_fill(s, n as u64);
        let b = r.produce(tx.clone()).await;
        fills.push((b.height(), tx));
        published.push(b);
    }
    assert_eq!(r.consensus.current_height(), AUTH_BOUNDARY - 1);

    // What the node knows about itself before it is stopped.
    let floor_before = undo_history_floor(&r.db).expect("floor");
    let watermark_before = persisted_format_high_water(&r.db).expect("watermark");
    let activation_before = JournalActivation::resolve(
        &r.db,
        ActivationSource::from_configured_height(
            genesis.params.application_journal_enabled_from_height,
        ),
    )
    .expect("resolve");
    assert_eq!(
        watermark_before,
        Some(FORMAT_VERSION_V1),
        "publishing must stamp the format watermark, or there is nothing for a \
         downgrade check to read after pruning"
    );
    assert_eq!(activation_before.boundary(), Some(JOURNAL_BOUNDARY));
    close(r);

    // ── the RESTART, through the real boot sequence ─────────────────────────
    boot(dir_r.path(), &genesis, Some(secret))
        .expect("a restart under an unchanged configuration must be permitted");

    // Everything the restart had to remember.
    let r = Producer::open(dir_r.path(), &genesis, secret);
    r.consensus
        .load_chain()
        .expect("load the chain from storage")
        .expect("a restarted node must find its own head");
    assert_eq!(
        r.consensus.current_height(),
        AUTH_BOUNDARY - 1,
        "the chain survives the restart"
    );
    assert_eq!(undo_history_floor(&r.db).expect("floor"), floor_before);
    assert_eq!(
        persisted_format_high_water(&r.db).expect("watermark"),
        watermark_before
    );
    assert_eq!(
        JournalActivation::resolve(
            &r.db,
            ActivationSource::from_configured_height(
                genesis.params.application_journal_enabled_from_height,
            ),
        )
        .expect("resolve")
        .boundary(),
        Some(JOURNAL_BOUNDARY),
        "the pinned journal boundary is CONFIGURATION and must be re-read, not \
         recovered from the database"
    );
    assert_eq!(
        read_recorded_heights(&r.db),
        genesis.params.recorded_activation_heights(),
        "the recorded activation heights must survive the restart unchanged"
    );

    // ── above the boundary, after the restart ───────────────────────────────
    for (n, s) in strangers.iter().enumerate().skip(3) {
        let tx = stranger_fill(s, n as u64);
        let b = r.produce(tx.clone()).await;
        fills.push((b.height(), tx));
        published.push(b);
    }
    let head = r.consensus.current_height();
    assert_eq!(head, 2 + strangers.len() as u64);
    assert!(head > AUTH_BOUNDARY, "the chain crossed the boundary");

    // The gate fired at exactly the configured height, and the restart is
    // squarely inside the run of blocks that crosses it.
    let mut below = 0;
    let mut above = 0;
    for (height, tx) in &fills {
        let expected = if *height >= AUTH_BOUNDARY {
            above += 1;
            (HEALTHCARE_FAILED, 0u128)
        } else {
            below += 1;
            (TxStatus::Success, FEE)
        };
        let receipt = ReceiptStore::new(&r.db)
            .get(&tx.hash())
            .expect("read")
            .unwrap_or_else(|| panic!("no receipt for the fill at height {height}"));
        assert_eq!(
            (receipt.status, receipt.fee_paid),
            expected,
            "the fill at height {height} under a boundary at {AUTH_BOUNDARY}"
        );
    }
    assert_eq!(below, 3);
    assert_eq!(above, 3);

    // ── the control: the same blocks, no restart ────────────────────────────
    let c = Producer::open(dir_c.path(), &genesis, secret);
    c.consensus.init_genesis(&genesis).expect("init genesis");
    for block in &published {
        c.consensus
            .import_block(block.clone())
            .await
            .unwrap_or_else(|e| panic!("the control must accept height {}: {e}", block.height()));
    }
    assert_eq!(c.consensus.current_height(), head);

    // Every row of every family, compared. The two differ in exactly the
    // families that record WHO DID WHAT rather than WHAT IS TRUE: the restarted
    // node produced these blocks and the control imported them, and the
    // application journal is a node-local undo record derived from each node's
    // own execution path.
    let left = r.snapshot();
    let right = c.snapshot();
    let families: std::collections::BTreeSet<&str> = left.keys().map(|(f, _)| f.as_str()).collect();
    assert!(
        families.len() > 10,
        "the comparison must cover the real store, not a handful of families: {}",
        families.len()
    );
    // The differing ROWS, named exactly. Two, and both are things a BOOT writes
    // rather than things an EXECUTION writes: the control was never booted
    // through `Node`, so it has neither the activation record nor the messaging
    // index-backfill marker. Compared as a key set rather than as a family set,
    // so a genuine execution difference inside either family would still fail.
    let expected_only_on_the_booted_node: std::collections::BTreeSet<(String, Vec<u8>)> = [
        (cf::META.to_string(), Node::ACTIVATION_META_KEY.to_vec()),
        (
            cf::MESSAGING_CONFIG.to_string(),
            sumchain_storage::messaging_store::config_keys::INDEX_BACKFILL_V1.to_vec(),
        ),
    ]
    .into_iter()
    .collect();
    let mut differing: std::collections::BTreeSet<(String, Vec<u8>)> = Default::default();
    for (key, value) in &left {
        match right.get(key) {
            Some(v) if v == value => {}
            _ => {
                differing.insert(key.clone());
            }
        }
    }
    for key in right.keys() {
        if !left.contains_key(key) {
            differing.insert(key.clone());
        }
    }
    assert_eq!(
        differing, expected_only_on_the_booted_node,
        "a restarted producer and an uninterrupted follower must agree on every \
         row of every family except the two a BOOT writes: the activation record \
         and the messaging index-backfill marker. Anything else here is an \
         execution difference the restart introduced"
    );

    close(r);
    close(c);

    // ── negative controls: the gate is live on the restart path ─────────────
    //
    // Without these, "the restart was permitted" and "nothing is checked" are
    // the same observation.

    // (a) Moving a gate the chain has ALREADY PASSED.
    let moved = genesis_for(&validator, &funded, Some(AUTH_BOUNDARY + 100));
    let refusal = boot(dir_r.path(), &moved, Some(secret))
        .expect_err("a gate the chain has already passed must not be rescheduled");
    assert!(
        refusal.contains("refusing to start")
            && refusal.contains("healthcare_authorization_enabled_from_height")
            && refusal.contains("ALREADY PASSED"),
        "the refusal must name the gate and say why: {refusal}"
    );

    // (b) Opening a gate RETROACTIVELY, below a head that already exists.
    let mut retro_params = genesis.params.clone();
    retro_params.nft_receipt_failure_enabled_from_height = Some(1);
    let retro = Genesis::new(
        CHAIN_ID,
        0,
        vec![validator.public_key().to_base58()],
        genesis.alloc.clone(),
        retro_params,
    );
    let refusal = boot(dir_r.path(), &retro, Some(secret))
        .expect_err("a gate set below the head must be refused");
    assert!(
        refusal.contains("refusing to start")
            && refusal.contains("nft_receipt_failure_enabled_from_height"),
        "the refusal must name the retroactively opened gate: {refusal}"
    );

    // (c) Rescheduling a gate still AHEAD of the chain is permitted — the thing
    //     the whole mechanism exists to allow. Run last because it rewrites the
    //     recorded heights.
    let mut ahead_params = genesis.params.clone();
    ahead_params.nft_receipt_failure_enabled_from_height = Some(head + 1_000);
    let ahead = Genesis::new(
        CHAIN_ID,
        0,
        vec![validator.public_key().to_base58()],
        genesis.alloc.clone(),
        ahead_params,
    );
    boot(dir_r.path(), &ahead, Some(secret))
        .expect("scheduling a gate ahead of the chain is a coordinated activation, not a fault");

    // (d) And the shape this test's OWN first boot had to avoid: a first start
    //     on a database that already holds blocks, with a gate this binary
    //     introduced set below the head. A fresh directory is given the same
    //     chain by import and then booted for the first time.
    let dir_x = tempfile::TempDir::new().expect("temp dir");
    let x = Producer::open(dir_x.path(), &genesis, secret);
    x.consensus.init_genesis(&genesis).expect("init genesis");
    for block in &published {
        x.consensus
            .import_block(block.clone())
            .await
            .expect("import");
    }
    close(x);
    let refusal = boot(dir_x.path(), &genesis, Some(secret)).expect_err(
        "a first boot on a database that already holds blocks must refuse a gate \
         this binary introduced and set below the head",
    );
    assert!(
        refusal.contains("has never recorded its activation heights")
            && refusal.contains("application_journal_enabled_from_height"),
        "the refusal must name the un-grandfathered gate: {refusal}"
    );
}

/// Read the persisted activation heights straight out of `cf::META`.
fn read_recorded_heights(db: &Database) -> Vec<(String, Option<u64>)> {
    let raw = db
        .get(cf::META, Node::ACTIVATION_META_KEY)
        .expect("read")
        .expect("the activation record must exist");
    bincode::deserialize(&raw).expect("decode")
}

/// The same, on a directory nothing currently holds open.
fn read_recorded_heights_at(dir: &Path) -> Vec<(String, Option<u64>)> {
    let db = Database::open_default(dir).expect("open");
    read_recorded_heights(&db)
}

// ═══════════════════════════════════════════════════════════════════════════
// 4. Downgrade refusal
// ═══════════════════════════════════════════════════════════════════════════

/// A database written under a NEWER application-journal record format refuses to
/// start under this binary — from the records, from the stamped watermark, and
/// from the stamped watermark ALONE once pruning has removed every record the
/// scan would otherwise have found.
///
/// # How an older binary is expressed
///
/// It cannot be, directly: this binary implements exactly one format and there
/// is no older one to run. The gate's condition is
/// `effective_high_water > FORMAT_VERSION_V1`, so the equivalent — and the only
/// reachable — arrangement is a database carrying a HIGHER version than this
/// binary implements, which is precisely the position an old binary is in when
/// it meets a new database. Both watermarks are written here the way a newer
/// binary would write them: the stamp is a two-byte big-endian row in `cf::META`
/// and the record's version field sits at a fixed offset after the magic.
///
/// # Why the pruned case is the one that matters
///
/// `highest_stored_format_version` is exact over the records that are PRESENT.
/// The pruner deletes records and does not delete the stamped row, so a database
/// whose newer records have aged out would pass a scan-only check and fail
/// during the first reorg instead. The third case below runs the REAL pruner, at
/// the REAL `UNDO_RETENTION_FLOOR`, until the journal family is empty, and
/// requires the refusal to survive.
#[tokio::test]
async fn a_database_holding_a_newer_record_format_refuses_to_start() {
    use sumchain_storage::journal::highest_stored_format_version;
    use sumchain_storage::pruner::{Pruner, PrunerConfig, UNDO_RETENTION_FLOOR};

    let validator = KeyPair::generate();
    let alice = KeyPair::generate();
    let bob = KeyPair::generate();
    let genesis = genesis_for(&validator, &[&alice, &bob], None);
    let secret = *validator.private_key().as_bytes();
    let dir = tempfile::TempDir::new().expect("temp dir");

    boot(dir.path(), &genesis, Some(secret)).expect("first boot on an empty database");

    // Real blocks, so the journal records and the stamp are written by the
    // production publish path rather than by the test.
    let p = Producer::open(dir.path(), &genesis, secret);
    p.consensus.init_genesis(&genesis).expect("init genesis");
    let mut blocks = Vec::new();
    for n in 0..4u64 {
        blocks.push(p.produce(transfer(&alice, bob.address(), 1_000, n)).await);
    }
    assert_eq!(p.consensus.current_height(), 4);
    assert_eq!(
        persisted_format_high_water(&p.db).expect("stamp"),
        Some(FORMAT_VERSION_V1),
        "every publish stamps the watermark; without a producer the row is a \
         reader with nothing to read"
    );
    assert_eq!(
        highest_stored_format_version(&p.db).expect("scan"),
        Some(FORMAT_VERSION_V1),
        "and the records carry the same version"
    );
    let journal_keys: Vec<Vec<u8>> = blocks
        .iter()
        .map(|b| sumchain_storage::schema::journal_key(b.height(), &b.hash()))
        .collect();
    for key in &journal_keys {
        assert!(
            p.db.get(cf::APPLICATION_JOURNAL, key)
                .expect("read")
                .is_some(),
            "every published block must have a journal record to age out later"
        );
    }
    close(p);

    // Baseline: this database starts.
    boot(dir.path(), &genesis, Some(secret))
        .expect("a database at this binary's own format must start");

    let future: u16 = FORMAT_VERSION_V1 + 1;

    // ── (a) the stamp alone ─────────────────────────────────────────────────
    {
        let db = Database::open_default(dir.path()).expect("open");
        db.put(cf::META, FORMAT_HIGH_WATER_META_KEY, &future.to_be_bytes())
            .expect("stamp a newer watermark");
        drop(db);
    }
    let refusal = boot(dir.path(), &genesis, Some(secret))
        .expect_err("a stamped newer format must refuse the start");
    assert!(
        refusal.contains("application journal format check failed")
            && refusal.contains(&format!("record format version {future}"))
            && refusal.contains(&format!("stamped: Some({future})")),
        "the refusal must name the newer version and where it was found: {refusal}"
    );
    assert!(
        refusal.contains("refuses to start") && refusal.contains("resyncing"),
        "and must say what an operator can do about it: {refusal}"
    );

    // ── (b) a record alone, with the stamp back at this binary's version ────
    {
        let db = Database::open_default(dir.path()).expect("open");
        db.put(
            cf::META,
            FORMAT_HIGH_WATER_META_KEY,
            &FORMAT_VERSION_V1.to_be_bytes(),
        )
        .expect("restore the stamp");
        // The version field sits at a fixed offset directly after the 5-byte
        // magic, which is how `highest_stored_format_version` reads it without
        // decoding the record.
        let key = &journal_keys[0];
        let mut raw = db
            .get(cf::APPLICATION_JOURNAL, key)
            .expect("read")
            .expect("record");
        raw[5..7].copy_from_slice(&future.to_be_bytes());
        db.put(cf::APPLICATION_JOURNAL, key, &raw)
            .expect("write a record in a newer format");
        drop(db);
    }
    let refusal = boot(dir.path(), &genesis, Some(secret))
        .expect_err("a newer record must refuse the start even with an old stamp");
    assert!(
        refusal.contains(&format!("record format version {future}")),
        "the scan must be the one that caught it: {refusal}"
    );

    // ── (c) the pruned case, which is the reason the stamped row exists ─────
    //
    // The stamp says `future`; the records are then DELETED by the real pruner,
    // at the real retention floor, until the scan can see nothing at all.
    {
        let db = Arc::new(Database::open_default(dir.path()).expect("open"));
        // Put the mutated record back to this binary's version first, so that
        // what survives into the next case is attributable to the STAMP and not
        // to a record the pruner happened to miss.
        let key = &journal_keys[0];
        let mut raw = db
            .get(cf::APPLICATION_JOURNAL, key)
            .expect("read")
            .expect("record");
        raw[5..7].copy_from_slice(&FORMAT_VERSION_V1.to_be_bytes());
        db.put(cf::APPLICATION_JOURNAL, key, &raw).expect("restore");
        db.put(cf::META, FORMAT_HIGH_WATER_META_KEY, &future.to_be_bytes())
            .expect("stamp a newer watermark");

        let pruner = Pruner::new(
            db.clone(),
            PrunerConfig {
                blocks_to_keep: 0,
                state_diffs_to_keep: 8,
                max_db_size_bytes: 0,
                compact_after_prune: false,
                enabled: true,
            },
        );
        assert_eq!(
            pruner.undo_retention(),
            UNDO_RETENTION_FLOOR,
            "the floor overrides the configuration, so this is the production \
             retention rule and not a test-only one"
        );
        // The pruner never deletes undo data within `UNDO_RETENTION_FLOOR` of
        // the head it is given, so the head it is given must be that far above
        // these records. This chain is four blocks long; the head is SUPPLIED
        // rather than reached, because reaching 4,096 real blocks is not what
        // this case is about. The code path, the floor and the deletion are the
        // production ones.
        let stats = pruner
            .prune(UNDO_RETENTION_FLOOR + 10)
            .expect("prune at the real floor");
        assert_eq!(
            stats.application_journals_pruned, 4,
            "the pruner must actually have deleted the records, or the next \
             assertion is about a database that was never pruned"
        );
        assert_eq!(
            highest_stored_format_version(&db).expect("scan"),
            None,
            "and the scan must now see nothing, which is exactly the state in \
             which a scan-only downgrade check would pass"
        );
        assert_eq!(
            persisted_format_high_water(&db).expect("stamp"),
            Some(future),
            "while the stamped row, which the pruner does not touch, still \
             records what was written"
        );
        drop(pruner);
        drop(db);
    }
    let refusal = boot(dir.path(), &genesis, Some(secret)).expect_err(
        "with every record pruned away, the stamped watermark alone must still \
         refuse the downgrade",
    );
    assert!(
        refusal.contains(&format!("record format version {future}"))
            && refusal.contains("present in records: None"),
        "the refusal must show that it fired on the STAMP with no records left: \
         {refusal}"
    );

    // ── the control: with the stamp back at this binary's version, the same
    //    record-less database starts ───────────────────────────────────────
    //
    // Without this, "an empty journal family refuses" and "the stamp refuses"
    // are the same observation.
    {
        let db = Database::open_default(dir.path()).expect("open");
        db.put(
            cf::META,
            FORMAT_HIGH_WATER_META_KEY,
            &FORMAT_VERSION_V1.to_be_bytes(),
        )
        .expect("restore the stamp");
        drop(db);
    }
    boot(dir.path(), &genesis, Some(secret)).expect(
        "a pruned database whose watermark this binary can read must start; the \
         refusals above are the STAMP's, not the empty family's",
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// 2 (the "refuse to start?" leg, through the real boot)
// ═══════════════════════════════════════════════════════════════════════════

/// Two validators whose activation heights DISAGREE both start.
///
/// `crates/consensus/tests/activation_multinode.rs` establishes what happens to
/// the blocks; this is the leg that needs the production boot sequence, because
/// "refuse to start" is a question only `Node::with_rpc_config` can answer.
///
/// It does not refuse, and it cannot: `check_activation_parameters` compares
/// this genesis against the heights THIS DATABASE was last started under. There
/// is no peer in the comparison and no place a peer could enter one — the
/// activation heights are distributed as a per-validator `genesis.json` and
/// nothing on the wire carries them.
///
/// What the boot does produce is the activation DIGEST, logged on every start,
/// and the two digests differ. That was, until the protocol digest existed, the
/// whole detection surface for this class of misconfiguration, and it is
/// operator-facing: two people comparing one value, not two files field by
/// field.
///
/// Both nodes STILL start, and that is deliberate. Boot is the wrong place to
/// refuse: a node that cannot start has no peers to compare itself against, and
/// a boot-time refusal derived from a database's own history can never see a
/// disagreement between two nodes. The refusal moved to the first moment a
/// second node is actually present — the peer handshake — where
/// `Node::run` compares the peer's declared `protocol_digest` against its own
/// and bans a mismatch (`crates/p2p/tests/protocol_compat.rs`).
///
/// So the verdict this test records is unchanged and still correct: boot accepts
/// both. What it now also records is that each node computes a DIFFERENT
/// protocol digest, which is the value the handshake will refuse on.
#[test]
fn two_validators_with_different_activation_heights_both_start() {
    let validator = KeyPair::generate();
    let alice = KeyPair::generate();
    let a = genesis_for(&validator, &[&alice], Some(AUTH_BOUNDARY));
    let b = genesis_for(&validator, &[&alice], Some(AUTH_BOUNDARY + 1));
    let secret = *validator.private_key().as_bytes();

    let dir_a = tempfile::TempDir::new().expect("temp dir");
    let dir_b = tempfile::TempDir::new().expect("temp dir");
    boot(dir_a.path(), &a, Some(secret)).expect("a validator on height A starts");
    boot(dir_b.path(), &b, Some(secret)).expect("a validator on height B starts too");

    // Each database records its OWN heights, and they differ. Nothing compares
    // one against the other, because nothing has both.
    let recorded_a = read_recorded_heights_at(dir_a.path());
    let recorded_b = read_recorded_heights_at(dir_b.path());
    assert_ne!(
        recorded_a, recorded_b,
        "the two nodes really are configured differently"
    );
    assert_eq!(
        recorded_a
            .iter()
            .find(|(g, _)| g == "healthcare_authorization_enabled_from_height")
            .map(|(_, h)| *h),
        Some(Some(AUTH_BOUNDARY))
    );
    assert_eq!(
        recorded_b
            .iter()
            .find(|(g, _)| g == "healthcare_authorization_enabled_from_height")
            .map(|(_, h)| *h),
        Some(Some(AUTH_BOUNDARY + 1))
    );

    // The one signal that exists.
    assert_ne!(
        a.activation_digest().expect("digest"),
        b.activation_digest().expect("digest"),
        "the activation digest is the only thing that distinguishes these two \
         configurations before a block is produced; if it did not move, a \
         one-digit difference would be invisible to every operator surface"
    );

    // The value the peer handshake compares, which is the same difference in a
    // form a NODE can act on rather than an operator. `Node::with_rpc_config`
    // computes exactly this and declares it to every peer that asks; a peer
    // declaring the other one is banned before it can offer a block.
    assert_ne!(
        sumchain_state::protocol_digest::protocol_digest(&a).expect("digest"),
        sumchain_state::protocol_digest::protocol_digest(&b).expect("digest"),
        "the protocol digest must distinguish these two configurations, or the \
         handshake refusal has nothing to fire on"
    );

    // And each node is happy to restart under its own configuration — the
    // refusal is about CHANGE on one database, not about disagreement between
    // two.
    boot(dir_a.path(), &a, Some(secret)).expect("restart on A");
    boot(dir_b.path(), &b, Some(secret)).expect("restart on B");
}
