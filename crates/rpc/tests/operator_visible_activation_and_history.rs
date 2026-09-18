//! What an operator can READ off a running node: the activation digest, and the
//! floor below which this node must not answer.
//!
//! The two values in this file exist for the same reason and are proven the same
//! way — through the RPC surface an operator actually calls, not through the
//! library functions underneath it. A digest that is correct in
//! `sumchain_genesis` and unreachable over JSON-RPC coordinates nothing, and a
//! history floor that is recorded in `cf::META` and ignored by the query paths
//! protects nothing.
//!
//! # `chain_getActivationStatus`
//!
//! Activation heights are distributed as a per-validator `genesis.json` and,
//! before this, compared by eye. `crates/genesis/tests/activation_digest.rs`
//! establishes that the digest is a function of the configuration and moves for
//! every difference that matters. What it cannot establish is that two NODES can
//! be compared: that requires the value to leave the process. These tests build
//! two servers the way production builds one and compare what they serve.
//!
//! # The state-history floor
//!
//! A node seeded from a state snapshot at height `h` holds no state and no
//! blocks below `h`. Every historical question below `h` has an honest answer
//! this node cannot produce — and, before this, an ordinary-looking answer it
//! produced anyway: `null` from a block lookup, an empty list, `false` from a
//! finality check, and, worst, a plausible node set from a backwards walk that
//! ran off the bottom of the history the machine holds. These tests pin the
//! refusal, its error code, and the line between "absent" and "I cannot know".

use std::collections::HashMap;
use std::sync::Arc;

use sumchain_consensus::{ConsensusEngine, PoAEngine};
use sumchain_crypto::KeyPair;
use sumchain_genesis::{ChainParams, Genesis};
use sumchain_rpc::api::SumChainApiServer;
use sumchain_rpc::auth::RpcAuthConfig;
use sumchain_rpc::metrics::Metrics;
use sumchain_rpc::rate_limit::RateLimitConfig;
use sumchain_rpc::server::RpcServer;
use sumchain_state::{Mempool, MempoolConfig, StateManager};
use sumchain_storage::Database;
use tokio::sync::mpsc;

const FLOOR: u64 = 900_000;

/// One node's RPC server, built through the same `with_*` chain
/// `crates/node/src/node.rs::build_rpc_server` uses, so what these tests read is
/// what a production node serves.
struct Served {
    _dir: tempfile::TempDir,
    db: Arc<Database>,
    server: RpcServer,
}

fn genesis_with(params: ChainParams) -> Genesis {
    let validator = KeyPair::from_bytes([7u8; 32]);
    Genesis::new(
        1,
        1_734_624_000_000,
        vec![validator.public_key().to_base58()],
        HashMap::from([(validator.address().to_base58(), 1_000_000u128)]),
        params,
    )
}

fn serve(genesis: &Genesis) -> Served {
    let dir = tempfile::TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let state = Arc::new(StateManager::new(db.clone(), genesis.chain_id));
    let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
    let validator = KeyPair::from_bytes([7u8; 32]);
    let engine: Arc<dyn ConsensusEngine> = Arc::new(
        PoAEngine::new(
            db.clone(),
            state.clone(),
            mempool.clone(),
            genesis,
            Some(validator),
        )
        .unwrap(),
    );
    let (tx_sender, _rx) = mpsc::channel(8);
    let server = RpcServer::with_full_config(
        db.clone(),
        state,
        mempool,
        engine,
        tx_sender,
        Arc::new(|| 0usize),
        Arc::new(|| None),
        Arc::new(|| true),
        RpcAuthConfig::disabled(),
        RateLimitConfig::disabled(),
        Arc::new(Metrics::new()),
    )
    .with_chain_params(genesis.params.clone())
    .with_genesis(genesis);
    Served {
        _dir: dir,
        db,
        server,
    }
}

/// A server with NO genesis wired, to pin what such a server may say.
fn serve_without_genesis(genesis: &Genesis) -> Served {
    let mut served = serve(genesis);
    let dir = tempfile::TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let state = Arc::new(StateManager::new(db.clone(), genesis.chain_id));
    let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
    let validator = KeyPair::from_bytes([7u8; 32]);
    let engine: Arc<dyn ConsensusEngine> = Arc::new(
        PoAEngine::new(
            db.clone(),
            state.clone(),
            mempool.clone(),
            genesis,
            Some(validator),
        )
        .unwrap(),
    );
    let (tx_sender, _rx) = mpsc::channel(8);
    served.server = RpcServer::with_full_config(
        db.clone(),
        state,
        mempool,
        engine,
        tx_sender,
        Arc::new(|| 0usize),
        Arc::new(|| None),
        Arc::new(|| true),
        RpcAuthConfig::disabled(),
        RateLimitConfig::disabled(),
        Arc::new(Metrics::new()),
    );
    served._dir = dir;
    served.db = db;
    served
}

/// A sound release-shaped pair, so the params under test are ones a node would
/// actually be allowed to start with.
fn sound(account: Option<u64>) -> ChainParams {
    let mut params = ChainParams::with_v2_enabled();
    params.application_journal_enabled_from_height = Some(600_000);
    params.account_root_enabled_from_height = account;
    params
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. The activation digest, as two operators actually compare it
// ─────────────────────────────────────────────────────────────────────────────

/// Two nodes whose chain-defined heights are identical serve an identical
/// digest; one block of difference on one gate serves a different one.
///
/// This is the claim the whole mechanism rests on, stated at the surface an
/// operator reads. Both halves matter and neither implies the other: a digest
/// that differed between identically-configured nodes would fire on every
/// comparison and be ignored within a week, and one that agreed across a
/// one-block difference would be worse than nothing, because it would certify
/// the exact typo it exists to catch.
#[tokio::test]
async fn two_nodes_with_identical_heights_serve_one_digest_and_a_one_block_difference_serves_another(
) {
    let a = serve(&genesis_with(sound(Some(13_800_000))));
    let b = serve(&genesis_with(sound(Some(13_800_000))));

    let sa = a.server.chain_get_activation_status().await.unwrap();
    let sb = b.server.chain_get_activation_status().await.unwrap();

    assert_eq!(
        sa.digest, sb.digest,
        "two nodes holding the same activation heights must serve the same \
         digest, or the comparison operators are told to perform reports a \
         disagreement that does not exist"
    );
    assert_eq!(sa.chain_id, sb.chain_id);
    // Not a placeholder: an "unavailable" string would also compare equal.
    assert!(
        !sa.digest.contains("unavailable") && sa.digest.len() >= 32,
        "the served digest must be the real value: {}",
        sa.digest
    );

    // One block. This is the mistyped digit, and it is the whole point.
    let c = serve(&genesis_with(sound(Some(13_800_001))));
    let sc = c.server.chain_get_activation_status().await.unwrap();
    assert_ne!(
        sa.digest, sc.digest,
        "a one-block difference on one gate must change the served digest"
    );

    // And the gate list served alongside it names the difference, so an operator
    // who sees two digests disagree can find out WHICH height moved without
    // diffing two files by hand.
    let height_of = |s: &sumchain_rpc::types::ActivationStatusInfo, gate: &str| {
        s.gates
            .iter()
            .find(|g| g.gate == gate)
            .unwrap_or_else(|| panic!("gate {gate} is not served"))
            .height
    };
    assert_eq!(
        height_of(&sa, "account_root_enabled_from_height"),
        Some(13_800_000)
    );
    assert_eq!(
        height_of(&sc, "account_root_enabled_from_height"),
        Some(13_800_001)
    );
}

/// The served digest is the value the library computes, so the number an
/// operator reads off a node and the number a release note names are the same
/// number.
///
/// Without this the RPC could serve a second, parallel digest that agreed with
/// itself across nodes and with nothing else.
#[tokio::test]
async fn the_served_digest_is_the_genesis_digest_and_not_a_second_one() {
    let genesis = genesis_with(sound(Some(13_800_000)));
    let expected = genesis.activation_digest().unwrap().to_string();
    let served = serve(&genesis);
    let status = served.server.chain_get_activation_status().await.unwrap();
    assert_eq!(status.digest, expected);
    assert_eq!(status.chain_id, genesis.chain_id);
}

/// `None` and `Some(0)` are opposite configurations and must not serve one
/// digest — checked HERE too, because the surface could flatten them.
///
/// The gate list carries `Option<u64>`, and a serialisation that turned `None`
/// into `0` would leave two nodes with opposite rules comparing equal on both
/// the digest and the field an operator would check next.
#[tokio::test]
async fn dormant_and_active_from_genesis_are_distinguishable_at_the_surface() {
    let dormant = serve(&genesis_with(sound(None)));
    let sd = dormant.server.chain_get_activation_status().await.unwrap();

    let mut from_zero = sound(None);
    // Genesis-height activation is only expressible on a gate the legacy-window
    // rule does not constrain; the contracts gate is one.
    from_zero.contracts_enabled_from_height = Some(0);
    let active = serve(&genesis_with(from_zero));
    let sa = active.server.chain_get_activation_status().await.unwrap();

    assert_ne!(sd.digest, sa.digest);
    let gate_of = |s: &sumchain_rpc::types::ActivationStatusInfo, g: &str| {
        s.gates.iter().find(|x| x.gate == g).unwrap().clone()
    };
    assert_eq!(gate_of(&sd, "contracts_enabled_from_height").height, None);
    assert_eq!(
        gate_of(&sa, "contracts_enabled_from_height").height,
        Some(0)
    );
    assert!(
        gate_of(&sa, "contracts_enabled_from_height").active,
        "a gate at height 0 is active at every height"
    );
}

/// A server built without a genesis says so rather than serving a digest over
/// defaults.
///
/// The dangerous failure is not "unavailable" — it is two such servers comparing
/// EQUAL, which is what a digest over `ChainParams::default()` would do for two
/// nodes that share nothing.
#[tokio::test]
async fn a_server_without_a_genesis_declines_rather_than_serving_a_default_digest() {
    let one = serve_without_genesis(&genesis_with(sound(Some(13_800_000))));
    let status = one.server.chain_get_activation_status().await.unwrap();
    assert!(
        status.digest.contains("unavailable"),
        "expected a refusal, got {}",
        status.digest
    );
    assert!(
        !one.server.has_genesis_identity(),
        "the tripwire predicate must agree with the served answer"
    );
    // And the node crate's production builder is what stops this reaching a real
    // node: `production_rpc_wires_contract_executor` asserts `has_genesis_identity`.
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. The state-history floor: "absent" against "I cannot know"
// ─────────────────────────────────────────────────────────────────────────────

/// Record a snapshot import, which is what makes a node's history floor
/// nonzero. The key and encoding belong to `sumchain_storage::journal`; this
/// reaches for the public recorder rather than writing the row, so a change to
/// that representation breaks the build here rather than silently producing a
/// node this test believes is restricted and which is not.
fn seed_import(db: &Database, height: u64) {
    sumchain_storage::journal::record_undo_history_floor(db, height).unwrap();
    assert_eq!(
        sumchain_state::snapshot::imported_at(db).unwrap(),
        Some(height),
        "the import must be readable back through the predicate the RPC uses"
    );
}

fn code(e: &jsonrpsee::types::ErrorObjectOwned) -> i32 {
    e.code()
}

/// `storage_getActiveNodesAtHeight` refuses below the floor — the one path whose
/// wrong answer is indistinguishable from a right one.
///
/// It walks BACKWARDS to the nearest snapshot. Below the floor that walk does
/// not run out of data and fail; it reaches the oldest record this machine
/// happens to hold and returns it, shaped exactly like a correct answer. The
/// refusal is therefore unconditional and happens before the walk.
#[tokio::test]
async fn the_active_node_set_is_refused_below_the_floor_before_the_walk_runs() {
    let served = serve(&genesis_with(sound(Some(13_800_000))));

    // Unrestricted first: the same call on a node that executed its own history
    // must still answer, or the guard has broken every archival node.
    served
        .server
        .storage_get_active_nodes_at_height(0)
        .await
        .expect("an unrestricted node must still answer");

    seed_import(&served.db, FLOOR);

    for height in [0, 1, FLOOR - 1] {
        let err = served
            .server
            .storage_get_active_nodes_at_height(height)
            .await
            .expect_err("below the floor this must refuse");
        assert_eq!(
            code(&err),
            -32003,
            "the refusal must carry the 'cannot know' code, not a generic one: {err:?}"
        );
        let text = err.message().to_string();
        assert!(
            text.contains(&FLOOR.to_string()) && text.contains("cannot know"),
            "the refusal must name the floor and say it is not a claim of \
             absence: {text}"
        );
    }

    // At the floor and above, the node holds state and answers.
    served
        .server
        .storage_get_active_nodes_at_height(FLOOR)
        .await
        .expect("at the floor this node holds state");
    served
        .server
        .storage_get_active_nodes_at_height(FLOOR + 1)
        .await
        .expect("above the floor too");
}

/// A block lookup distinguishes the two answers: found is found, absent above
/// the floor is `null`, absent below it is a refusal.
///
/// The middle case is the one that makes this a distinction rather than a
/// blanket refusal. A node may legitimately have no block at a height it is
/// entitled to answer for — it has not reached that height yet — and `null` is
/// the right answer there. `null` for a height that was never on the machine is
/// a claim about the chain that this node cannot support.
#[tokio::test]
async fn a_block_lookup_says_absent_or_says_it_cannot_know_but_never_confuses_them() {
    let served = serve(&genesis_with(sound(Some(13_800_000))));

    // Unrestricted: absence is absence.
    assert!(served
        .server
        .get_block_by_height(FLOOR - 1)
        .await
        .expect("an unrestricted node answers null for a height it has not reached")
        .is_none());

    seed_import(&served.db, FLOOR);

    let err = served
        .server
        .get_block_by_height(FLOOR - 1)
        .await
        .expect_err("below the floor an absence is not an answer");
    assert_eq!(code(&err), -32003);

    // Above the floor, the same absence is a real `null` — this node is
    // entitled to say the chain has nothing there.
    assert!(
        served
            .server
            .get_block_by_height(FLOOR + 5)
            .await
            .expect("above the floor the node may answer")
            .is_none(),
        "above the floor an absent block is absent, not a refusal"
    );

    // The sum_* alias is the same method and must not be a way around the rule.
    let err = served
        .server
        .sum_get_block_by_height(FLOOR - 1)
        .await
        .expect_err("the alias must refuse identically");
    assert_eq!(code(&err), -32003);
}

/// A range query fails whole rather than returning a short list.
///
/// A truncated range is not visibly truncated: a caller that asked for ten
/// blocks and received four reads it as "the chain has four there". This is the
/// same confusion as `null`, with a larger blast radius.
#[tokio::test]
async fn a_block_range_crossing_the_floor_fails_whole_rather_than_truncating() {
    let served = serve(&genesis_with(sound(Some(13_800_000))));
    seed_import(&served.db, FLOOR);

    let err = served
        .server
        .get_blocks(FLOOR - 4, FLOOR + 4)
        .await
        .expect_err("a range crossing the floor must not return a partial list");
    assert_eq!(code(&err), -32003);
    assert!(err.message().contains(&FLOOR.to_string()));
}

/// `is_block_finalized` refuses rather than answering `false`.
///
/// `false` means "not yet final", and a caller polls on it. Below the floor that
/// poll never terminates, on a block that finalised long before this node
/// existed.
#[tokio::test]
async fn a_finality_check_below_the_floor_refuses_rather_than_answering_not_final() {
    let served = serve(&genesis_with(sound(Some(13_800_000))));
    assert!(
        !served.server.is_block_finalized(FLOOR - 1).await.unwrap(),
        "unrestricted, this is an ordinary `false`"
    );

    seed_import(&served.db, FLOOR);
    let err = served
        .server
        .is_block_finalized(FLOOR - 1)
        .await
        .expect_err("below the floor `false` would be a lie of omission");
    assert_eq!(code(&err), -32003);
}

/// An empty message list below the floor is a refusal, not "that block carried
/// no messages".
#[tokio::test]
async fn an_empty_message_list_below_the_floor_is_a_refusal() {
    let served = serve(&genesis_with(sound(Some(13_800_000))));
    assert!(served
        .server
        .messaging_get_messages_in_block(FLOOR - 1, None)
        .await
        .unwrap()
        .is_empty());

    seed_import(&served.db, FLOOR);
    let err = served
        .server
        .messaging_get_messages_in_block(FLOOR - 1, None)
        .await
        .expect_err("below the floor an empty list is indistinguishable from no history");
    assert_eq!(code(&err), -32003);
}

/// The floor an operator can READ is the floor the query paths ENFORCE.
///
/// Two different numbers here would be the worst outcome of all: an operator
/// sizing their archival coverage off `chain_getSyncCapability` while the node
/// refuses — or, far worse, answers — at a different height.
#[tokio::test]
async fn the_advertised_floor_and_the_enforced_floor_are_the_same_number() {
    let served = serve(&genesis_with(sound(Some(13_800_000))));
    let cap = served.server.chain_get_sync_capability().await.unwrap();
    assert_eq!(cap.state_history_floor, None);
    assert_eq!(cap.imported_at, None);

    seed_import(&served.db, FLOOR);
    let cap = served.server.chain_get_sync_capability().await.unwrap();
    let advertised = cap
        .state_history_floor
        .expect("an imported node must advertise a floor");
    assert_eq!(advertised, FLOOR);
    assert_eq!(cap.imported_at, Some(FLOOR));
    assert_eq!(
        cap.journal_history_begins_at,
        Some(FLOOR + 1),
        "and the undo history begins one block above it"
    );

    // Enforced at exactly that number, on both sides.
    assert!(served
        .server
        .storage_get_active_nodes_at_height(advertised - 1)
        .await
        .is_err());
    assert!(served
        .server
        .storage_get_active_nodes_at_height(advertised)
        .await
        .is_ok());
}

/// A restored node does not ADVERTISE history it lacks, and says fast sync is
/// unavailable in the same breath.
///
/// The three claims a node makes about its own history — what it can serve, how
/// deep it can reorg, and whether it could seed another node — all read from one
/// recorded import height, and this pins that they move together.
#[tokio::test]
async fn a_restored_node_advertises_no_more_than_it_holds() {
    let served = serve(&genesis_with(sound(Some(13_800_000))));
    seed_import(&served.db, FLOOR);

    let cap = served.server.chain_get_sync_capability().await.unwrap();
    assert_eq!(
        cap.usable_reorg_depth, 0,
        "at the restore height a node can unwind nothing: it holds no undo \
         records at or below it"
    );
    assert!(
        !cap.fast_sync_available,
        "this binary's snapshot format cannot seed a node"
    );
    assert!(
        !cap.missing_families.is_empty(),
        "and the refusal must name what is missing rather than being a flag"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. The one provenance a node carries that its own execution did not produce
// ─────────────────────────────────────────────────────────────────────────────

/// OC-2. A node whose SRC-201 registry was SEEDED by an operator says so to any
/// peer that asks, and says the same thing every node compares against.
///
/// `cf::MESSAGING_PUBLIC_KEYS` is read by consensus, so two nodes holding
/// different registries produce different receipts for identical blocks and
/// therefore different state roots. `sumchain import-registered-keys` refuses
/// above genesis, which stops the mid-chain write; what it cannot stop is two
/// validators seeding DIFFERENT sets at genesis, because the rows look the same
/// either way and neither node has executed anything yet to disagree about.
///
/// The digest is the answer to that, and it is only an answer if it leaves the
/// process: a marker that lives in `cf::META` and is invisible over JSON-RPC
/// coordinates nothing, for the same reason the activation digest above does
/// not. This drives the real handler.
#[tokio::test]
async fn a_seeded_messaging_registry_is_visible_to_a_peer_and_two_seeds_are_comparable() {
    use sumchain_primitives::{Address, RegisteredPublicKey};
    use sumchain_storage::messaging_store::MessagingStore;

    fn key(n: u8) -> (Address, RegisteredPublicKey) {
        let public_key = [n; 32];
        let address = Address::from_public_key(&public_key);
        (
            address,
            RegisteredPublicKey {
                public_key,
                address,
                registered_at_block: 0,
                registered_at: 1_700_000_000,
                updated_at_block: 0,
            },
        )
    }

    // A node that executed its own history claims no seed. That absence is a
    // positive claim and it is the normal one.
    let unseeded = serve(&genesis_with(sound(Some(13_800_000))));
    let cap = unseeded.server.chain_get_sync_capability().await.unwrap();
    assert!(
        cap.messaging_registry_seed.is_none(),
        "a node whose registry came from its own execution must not claim a seed"
    );

    let a = serve(&genesis_with(sound(Some(13_800_000))));
    let written = MessagingStore::new(&a.db)
        .seed_registry_at_genesis(None, &[key(1), key(2), key(3)])
        .expect("seeding an empty registry at genesis is the supported shape");

    let cap = a.server.chain_get_sync_capability().await.unwrap();
    let seen = cap
        .messaging_registry_seed
        .expect("a seeded node must say so on the surface a peer reads");
    assert_eq!(seen.key_count, 3);
    assert_eq!(seen.seeded_at_height, 0);
    assert_eq!(
        seen.digest, written.digest,
        "the served digest is the recorded one; two numbers here would be worse \
         than none, because operators would compare the wrong one"
    );

    // A second validator seeded from the same set agrees, in a different order.
    let b = serve(&genesis_with(sound(Some(13_800_000))));
    MessagingStore::new(&b.db)
        .seed_registry_at_genesis(None, &[key(3), key(1), key(2)])
        .unwrap();
    let their = b
        .server
        .chain_get_sync_capability()
        .await
        .unwrap()
        .messaging_registry_seed
        .unwrap();
    assert_eq!(
        their.digest, seen.digest,
        "two validators seeded from the same registrations must be able to \
         establish that they agree"
    );

    // And one seeded from a different set does not — which is the comparison
    // that has to work, because it is the fork.
    let c = serve(&genesis_with(sound(Some(13_800_000))));
    MessagingStore::new(&c.db)
        .seed_registry_at_genesis(None, &[key(1), key(2), key(4)])
        .unwrap();
    let diverged = c
        .server
        .chain_get_sync_capability()
        .await
        .unwrap()
        .messaging_registry_seed
        .unwrap();
    assert_eq!(diverged.key_count, seen.key_count, "the same count, and");
    assert_ne!(
        diverged.digest, seen.digest,
        "a different set. A count alone would certify this pair as matching"
    );
}
