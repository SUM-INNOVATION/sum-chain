//! What a peer can and cannot get into consensus, driven against a REAL engine
//! on a REAL database.
//!
//! # What these tests prove that a source scan cannot
//!
//! `crates/node/tests/consensus_participation_guard.rs` reads `node.rs` as text.
//! It can assert that a check is written and written first; it cannot assert
//! that the check DOES anything, and a predicate that returned `true`
//! unconditionally would pass every line of it.
//!
//! These tests call `Node::admit_peer_block` — the function both block-carrying
//! arms of the event loop call, and the only place in `crates/node/src` that
//! calls `consensus.import_block` — with a real `PoAEngine` behind it, and then
//! ask the BLOCK STORE what happened. A refusal is proven by the block's absence
//! from `BlockStore` and by the chain head not moving, which is the property an
//! operator actually cares about.
//!
//! # What they still do not prove
//!
//! That `Node::run`'s event loop calls `admit_peer_block` at all. `Node::run` is
//! one ~900-line `async fn` that binds an RPC port, a health port and a libp2p
//! listener before its first `select!`, so there is no seam at which a test can
//! hand it a `NetworkEvent`. That wiring — the arm bodies, and the claim that
//! `consensus.import_block` appears exactly once in the file — stays a source
//! scan, in `consensus_participation_guard.rs`. The fusing of the check and the
//! import into ONE function is what shrinks that scan from "two call sites are
//! each correctly ordered" to "there is one call site and it is behind the
//! predicate".
//!
//! The RESTART tests below are different: they drive `Node::with_rpc_config`,
//! the real boot, twice on the same directory, so what they assert about a
//! restarted node's compatibility state is behaviour and not text.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use sumchain_consensus::ConsensusEngine;
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::{ChainParams, Genesis};
use sumchain_p2p::{PeerCompat, PeerCompatRegistry, PeerId};
use sumchain_primitives::{Block, BlockHeight, Hash, SignedTransaction, Transaction};
use sumchain_state::{Mempool, MempoolConfig, StateManager};
use sumchain_storage::{BlockStore, Database};

use crate::consensus_wrapper::ConsensusWrapper;

use super::{Node, PeerBlockOutcome};

const CHAIN_ID: u64 = 1;

/// The height from which an undeclared peer stops being admitted, and — because
/// `Genesis::validate` refuses a remediation gate without one — also the height
/// at which the remediated rules begin. Small so the fixture can actually reach
/// it: the property under test is the comparison `height >= from`, which does
/// not care whether `from` is 3 or 3,000,000.
const ENFORCE_FROM: BlockHeight = 3;

/// A chain tip above the boundary, so every test has blocks on both sides.
const TIP: BlockHeight = 5;

// ─────────────────────────────────────────────────────────────────────────────
// Fixture
// ─────────────────────────────────────────────────────────────────────────────

fn genesis_for(validator: &KeyPair, funded: &KeyPair) -> Genesis {
    let mut params = ChainParams::with_v2_enabled();
    params.peer_protocol_declaration_required_from_height = Some(ENFORCE_FROM);
    params.finality_depth = 1_000_000;
    let mut alloc = HashMap::new();
    alloc.insert(validator.address().to_base58(), 100_000_000u128);
    alloc.insert(funded.address().to_base58(), 100_000_000u128);
    let g = Genesis::new(
        CHAIN_ID,
        0,
        vec![validator.public_key().to_base58()],
        alloc,
        params,
    );
    Genesis::from_json(&g.to_json().expect("serialize")).expect("genesis must validate")
}

/// A consensus stack on a directory, with the compatibility registry the node
/// would have built for the same genesis.
struct Stack {
    db: Arc<Database>,
    #[allow(dead_code)]
    state: Arc<StateManager>,
    mempool: Arc<Mempool>,
    consensus: ConsensusWrapper,
    compat: Arc<PeerCompatRegistry>,
}

impl Stack {
    fn open(dir: &Path, genesis: &Genesis, validator: Option<&KeyPair>) -> Self {
        let db = Arc::new(Database::open_default(dir).expect("open database"));
        let state = Arc::new(StateManager::new(db.clone(), CHAIN_ID));
        let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
        let consensus = ConsensusWrapper::new_poa(
            db.clone(),
            state.clone(),
            mempool.clone(),
            genesis,
            validator.map(|k| KeyPair::from_bytes(*k.private_key().as_bytes())),
        )
        .expect("engine");
        consensus.init_genesis(genesis).expect("init genesis");
        // Exactly the construction `Node::with_rpc_config` performs: this
        // binary's protocol digest for this genesis, and the enforcement height
        // read from `ChainParams`.
        let digest =
            sumchain_state::protocol_digest::protocol_digest(genesis).expect("protocol digest");
        let compat = Arc::new(PeerCompatRegistry::new(
            digest,
            genesis
                .params
                .peer_protocol_declaration_required_from_height,
        ));
        Self {
            db,
            state,
            mempool,
            consensus,
            compat,
        }
    }

    /// Our digest — what a compatible peer declares.
    fn ours(&self) -> Hash {
        self.compat.protocol_digest()
    }

    async fn produce(&self, tx: SignedTransaction) -> Block {
        self.mempool.add(tx).expect("mempool accepts");
        let txs = self.mempool.select_for_block(100);
        assert_eq!(txs.len(), 1, "one transaction per block in this fixture");
        // Through the PoA engine directly: `ConsensusWrapper` deliberately
        // exposes no `propose_block`, because production block production is
        // `run_block_producer`, not a call anything outside consensus makes.
        self.consensus
            .as_poa()
            .expect("the fixture is PoA")
            .propose_block(txs)
            .await
            .expect("propose block")
    }

    /// Whether the engine actually holds this block.
    ///
    /// The question a refusal has to answer. `PoAEngine::do_import_block`
    /// (`crates/consensus/src/poa.rs:603`) writes through `BlockStore` on every
    /// admission path it has — direct extension, side branch and reorg — so a
    /// block absent from the store is a block the engine never accepted.
    fn holds(&self, block: &Block) -> bool {
        BlockStore::new(&self.db)
            .contains(&block.hash())
            .expect("read the block store")
    }

    async fn admit(&self, peer: &PeerId, block: &Block) -> PeerBlockOutcome {
        Node::admit_peer_block(&self.compat, &self.consensus, peer, block.clone()).await
    }
}

fn transfer(from: &KeyPair, to: &KeyPair, nonce: u64) -> SignedTransaction {
    let tx = Transaction::new(CHAIN_ID, from.address(), to.address(), 1, 10, nonce);
    let sig = sign(tx.signing_hash().as_bytes(), from.private_key());
    SignedTransaction::new(tx, *sig.as_bytes(), *from.public_key().as_bytes())
}

/// A real chain of `TIP` blocks, produced by a real validator on its own
/// directory. Returned by height so a test can pick a block on either side of
/// the boundary.
///
/// The `TempDir` is returned alive: dropping it takes the producer's database
/// with it, and the blocks are then the only thing left, which is exactly the
/// shape of a peer supplying blocks this node did not produce.
async fn a_chain() -> (KeyPair, KeyPair, Genesis, Vec<Block>, tempfile::TempDir) {
    let validator = KeyPair::generate();
    let funded = KeyPair::generate();
    let genesis = genesis_for(&validator, &funded);
    let dir = tempfile::TempDir::new().expect("temp dir");
    let producer = Stack::open(dir.path(), &genesis, Some(&validator));

    let mut blocks = Vec::new();
    for n in 0..TIP {
        let block = producer.produce(transfer(&funded, &validator, n)).await;
        assert_eq!(
            block.height(),
            n + 1,
            "the fixture must produce consecutive heights"
        );
        blocks.push(block);
    }
    assert!(
        blocks.iter().any(|b| b.height() < ENFORCE_FROM)
            && blocks.iter().any(|b| b.height() >= ENFORCE_FROM),
        "the fixture must straddle the enforcement height or it proves one phase"
    );
    (validator, funded, genesis, blocks, dir)
}

/// A fresh node that produced none of these blocks — the importer under test.
fn importer(genesis: &Genesis) -> (Stack, tempfile::TempDir) {
    let dir = tempfile::TempDir::new().expect("temp dir");
    let s = Stack::open(dir.path(), genesis, None);
    (s, dir)
}

// ═════════════════════════════════════════════════════════════════════════════
// 1. Undeclared, above the boundary: neither route works
// ═════════════════════════════════════════════════════════════════════════════

/// A peer that has declared nothing cannot gossip a block into consensus at or
/// above the enforcement height.
///
/// The refusal is asserted against the BLOCK STORE, not against the predicate:
/// the block is absent and the head has not moved, so nothing validated it,
/// nothing classified it against fork choice and nothing published it.
#[tokio::test]
async fn an_undeclared_peer_cannot_gossip_a_block_into_consensus_above_the_boundary() {
    let (_v, _f, genesis, blocks, _producer_dir) = a_chain().await;
    let (node, _dir) = importer(&genesis);
    let peer = PeerId::random();

    // Feed everything below the boundary first, so the parent of the refused
    // block is present and `ParentNotFound` cannot be the reason it is missing.
    for b in blocks.iter().filter(|b| b.height() < ENFORCE_FROM) {
        assert!(
            matches!(node.admit(&peer, b).await, PeerBlockOutcome::Imported),
            "height {} is below the enforcement height and must import",
            b.height()
        );
    }
    let head_before = node.consensus.current_height();
    assert_eq!(head_before, ENFORCE_FROM - 1);

    let first_gated = blocks
        .iter()
        .find(|b| b.height() == ENFORCE_FROM)
        .expect("a block at the boundary");
    assert!(
        node.consensus
            .get_block_by_height(first_gated.height() - 1)
            .is_some(),
        "the parent is on disk, so the only thing that can refuse this block is \
         the participation check"
    );

    let outcome = node.admit(&peer, first_gated).await;
    assert!(
        matches!(outcome, PeerBlockOutcome::Refused(PeerCompat::Undeclared)),
        "a peer that declared nothing must be refused at height {ENFORCE_FROM}, \
         got {outcome:?}"
    );
    assert!(
        !node.holds(first_gated),
        "the refused block {} is in the block store, so `do_import_block` ran: \
         it was validated, classified against fork choice and published by a \
         peer this node cannot show agrees with it",
        first_gated.hash()
    );
    assert_eq!(
        node.consensus.current_height(),
        head_before,
        "the chain head moved on a refused block"
    );

    // And every later block too — the refusal is not a one-block hiccup.
    for b in blocks.iter().filter(|b| b.height() > ENFORCE_FROM) {
        let o = node.admit(&peer, b).await;
        assert!(
            matches!(o, PeerBlockOutcome::Refused(PeerCompat::Undeclared)),
            "height {} must also be refused, got {o:?}",
            b.height()
        );
        assert!(!node.holds(b));
    }
}

/// The same peer, the same blocks, arriving by SYNC instead of gossip.
///
/// Sync is a different `NetworkEvent` carrying a BATCH, and the batch can
/// straddle the boundary: the blocks below it are ones this peer was entitled to
/// supply and the blocks at or above it are not. The verdict is therefore per
/// block, and this test drives the batch through the same seam the sync arm
/// uses, asserting where the store stops.
///
/// Two independent gates cover this route and both are exercised behaviourally:
/// `BlockSyncer::on_blocks_received` filters the batch inside `sumchain-p2p`
/// before the node ever sees it (`crates/p2p/tests/protocol_enforcement.rs`),
/// and `Node::admit_peer_block` refuses it again here. The `break` that ends the
/// sync loop on a refusal lives in `Node::run` and is source-scanned.
#[tokio::test]
async fn an_undeclared_peer_cannot_sync_a_block_into_consensus_above_the_boundary() {
    let (_v, _f, genesis, blocks, _producer_dir) = a_chain().await;
    let (node, _dir) = importer(&genesis);
    let peer = PeerId::random();

    // The sync arm's loop shape: per block, stop at the first refusal.
    let mut imported = Vec::new();
    let mut refused_at = None;
    for b in &blocks {
        match node.admit(&peer, b).await {
            PeerBlockOutcome::Imported => imported.push(b.height()),
            PeerBlockOutcome::Refused(status) => {
                refused_at = Some((b.height(), status));
                break;
            }
            PeerBlockOutcome::ImportFailed(e) => {
                panic!("height {} failed to import: {e}", b.height())
            }
        }
    }

    assert_eq!(
        imported,
        (1..ENFORCE_FROM).collect::<Vec<_>>(),
        "exactly the blocks below the enforcement height may be taken from an \
         undeclared peer"
    );
    assert_eq!(
        refused_at,
        Some((ENFORCE_FROM, PeerCompat::Undeclared)),
        "the batch must be cut at the boundary, not accepted whole and not \
         refused whole"
    );
    for b in &blocks {
        assert_eq!(
            node.holds(b),
            b.height() < ENFORCE_FROM,
            "block at height {} is {} the store",
            b.height(),
            if node.holds(b) { "in" } else { "absent from" }
        );
    }
    assert_eq!(node.consensus.current_height(), ENFORCE_FROM - 1);
}

// ═════════════════════════════════════════════════════════════════════════════
// 2. Declared and matching: admitted, on both sides
// ═════════════════════════════════════════════════════════════════════════════

/// A peer declaring OUR digest supplies blocks below and above the boundary.
///
/// The control for every refusal above. Without it, a predicate wired to
/// `false` would pass the refusal tests and fail nothing.
#[tokio::test]
async fn a_matching_peer_supplies_blocks_on_both_sides_of_the_boundary() {
    let (_v, _f, genesis, blocks, _producer_dir) = a_chain().await;
    let (node, _dir) = importer(&genesis);
    let peer = PeerId::random();

    assert!(
        node.compat.on_declaration(peer, node.ours()),
        "declaring our own digest must be accepted as a match"
    );
    assert_eq!(node.compat.status(&peer), PeerCompat::Verified);

    for b in &blocks {
        let o = node.admit(&peer, b).await;
        assert!(
            matches!(o, PeerBlockOutcome::Imported),
            "a verified peer's block at height {} must import, got {o:?}",
            b.height()
        );
        assert!(node.holds(b));
    }
    assert_eq!(
        node.consensus.current_height(),
        TIP,
        "a verified peer must be able to carry this node all the way to the tip, \
         across the enforcement height"
    );
}

/// A peer too old to understand `GetProtocolId` at all, below the boundary.
///
/// This is every validator running today: it cannot decode the request, answers
/// with an inbound failure, and so declares nothing, forever. Below the
/// enforcement height it must be exactly as usable as it is now — a refusal that
/// fired here would be worse than the defect the mechanism closes.
#[tokio::test]
async fn a_pre_feature_peer_below_the_boundary_is_unaffected() {
    let (_v, _f, genesis, blocks, _producer_dir) = a_chain().await;
    let (node, _dir) = importer(&genesis);
    let peer = PeerId::random();

    // Nothing is recorded for it, ever. Not a declaration of silence — an
    // absence, which is what a binary with no such message produces.
    assert_eq!(node.compat.status(&peer), PeerCompat::Undeclared);

    for b in blocks.iter().filter(|b| b.height() < ENFORCE_FROM) {
        let o = node.admit(&peer, b).await;
        assert!(
            matches!(o, PeerBlockOutcome::Imported),
            "height {} is below the enforcement height and a silent peer must be \
             as usable as it is today, got {o:?}",
            b.height()
        );
        assert!(node.holds(b));
    }
    assert_eq!(node.consensus.current_height(), ENFORCE_FROM - 1);
}

/// The same pre-feature peer on a genesis that never sets the height.
///
/// Every `genesis.json` distributed before the field existed resolves it to
/// `None`, which is phase one forever. The mechanism has to be completely inert
/// on such a chain, at every height, including heights far above where any
/// operator would have written a boundary.
#[tokio::test]
async fn a_pre_feature_peer_on_a_pre_feature_genesis_is_never_refused() {
    let validator = KeyPair::generate();
    let funded = KeyPair::generate();
    let mut params = ChainParams::with_v2_enabled();
    params.finality_depth = 1_000_000;
    assert_eq!(
        params.peer_protocol_declaration_required_from_height, None,
        "the default must be `None`, or shipping this binary changes behaviour \
         on every chain that never asked for it"
    );
    let mut alloc = HashMap::new();
    alloc.insert(validator.address().to_base58(), 100_000_000u128);
    alloc.insert(funded.address().to_base58(), 100_000_000u128);
    let genesis = Genesis::from_json(
        &Genesis::new(
            CHAIN_ID,
            0,
            vec![validator.public_key().to_base58()],
            alloc,
            params,
        )
        .to_json()
        .expect("serialize"),
    )
    .expect("genesis must validate");

    let pdir = tempfile::TempDir::new().expect("temp dir");
    let producer = Stack::open(pdir.path(), &genesis, Some(&validator));
    let mut blocks = Vec::new();
    for n in 0..TIP {
        blocks.push(producer.produce(transfer(&funded, &validator, n)).await);
    }

    let (node, _dir) = importer(&genesis);
    assert_eq!(node.compat.enforcement_height(), None);
    let peer = PeerId::random();
    for b in &blocks {
        let o = node.admit(&peer, b).await;
        assert!(
            matches!(o, PeerBlockOutcome::Imported),
            "with no enforcement height configured, height {} must import from a \
             silent peer, got {o:?}",
            b.height()
        );
    }
    assert_eq!(node.consensus.current_height(), TIP);
}

// ═════════════════════════════════════════════════════════════════════════════
// 3. Declared and mismatching: refused in both phases
// ═════════════════════════════════════════════════════════════════════════════

/// A peer declaring a DIFFERENT digest is refused below the boundary too, and
/// cannot declare its way back in.
///
/// The one case that is genuinely new behaviour, and the one no node predating
/// the handshake can ever fall into: producing a mismatching digest requires
/// understanding the request in the first place.
#[tokio::test]
async fn a_mismatching_peer_is_refused_in_both_phases_and_cannot_recant() {
    let (_v, _f, genesis, blocks, _producer_dir) = a_chain().await;
    let (node, _dir) = importer(&genesis);
    let peer = PeerId::random();

    let theirs = Hash::hash(b"a different binary's protocol digest");
    assert_ne!(theirs, node.ours());
    assert!(
        !node.compat.on_declaration(peer, theirs),
        "a mismatching declaration must be reported as a refusal"
    );
    assert_eq!(node.compat.status(&peer), PeerCompat::Incompatible);

    // Below the boundary, where an undeclared peer is welcome.
    let low = blocks
        .iter()
        .find(|b| b.height() < ENFORCE_FROM)
        .expect("a block below the boundary");
    let o = node.admit(&peer, low).await;
    assert!(
        matches!(o, PeerBlockOutcome::Refused(PeerCompat::Incompatible)),
        "a peer that said it enforces other rules is refused at every height, \
         including heights where silence is admitted, got {o:?}"
    );
    assert!(!node.holds(low));

    // It now declares the right digest. It does not get back in: the first
    // answer was an admission, and a second is at best a different binary.
    assert!(
        !node.compat.on_declaration(peer, node.ours()),
        "a peer that once declared a mismatch must not be re-admitted by \
         declaring a match"
    );
    assert_eq!(node.compat.status(&peer), PeerCompat::Incompatible);
    let o = node.admit(&peer, low).await;
    assert!(
        matches!(o, PeerBlockOutcome::Refused(PeerCompat::Incompatible)),
        "got {o:?}"
    );
    assert!(!node.holds(low));
    assert_eq!(
        node.consensus.current_height(),
        0,
        "not one block from a mismatching peer reached the engine"
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// 4. Restart, through the REAL boot
// ═════════════════════════════════════════════════════════════════════════════

/// A `Node` built the way production builds one, on `dir`.
fn boot(dir: &Path, genesis: &Genesis, secret: [u8; 32]) -> Node {
    let rpc: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let health: SocketAddr = "127.0.0.1:0".parse().unwrap();
    Node::with_rpc_config(
        dir.to_path_buf(),
        genesis.clone(),
        Some(KeyPair::from_bytes(secret)),
        sumchain_p2p::NetworkConfig::default(),
        rpc,
        health,
        sumchain_rpc::RpcAuthConfig::disabled(),
        sumchain_rpc::RateLimitConfig::disabled(),
        crate::config::ConsensusSettings::default(),
    )
    .expect("the real boot must succeed")
}

/// What a restart does to a peer this node had already verified.
///
/// The answer is not "nothing", and that is worth writing down. `PeerCompat` is
/// held in `PeerCompatRegistry::declared`, a `RwLock<HashMap>` built empty by
/// `Node::with_rpc_config` and persisted nowhere. So a restarted node has
/// forgotten every declaration, and a peer it verified an hour ago is
/// `Undeclared` again — which above the enforcement height means REFUSED until
/// it declares again.
///
/// That is correct, and it is only safe because the node re-asks: the
/// `NetworkEvent::PeerConnected` arm sends `NetworkCommand::RequestProtocolId`
/// to every peer as it connects, and a restart reconnects everything. The window
/// is one request/response round trip per peer, during which a matching peer's
/// blocks are refused rather than accepted — the failure is toward refusal, not
/// toward admission, which is the direction this mechanism must fail in.
///
/// The test drives the real boot twice on the same directory so that the
/// forgetting is observed rather than assumed.
#[tokio::test]
async fn a_verified_peer_must_declare_again_after_a_restart_and_is_then_admitted() {
    let validator = KeyPair::generate();
    let funded = KeyPair::generate();
    let genesis = genesis_for(&validator, &funded);
    let secret = *validator.private_key().as_bytes();
    let dir = tempfile::TempDir::new().expect("temp dir");
    let peer = PeerId::random();

    // ── run 1 ───────────────────────────────────────────────────────────────
    let first = boot(dir.path(), &genesis, secret);
    let digest_before = first.protocol_digest;
    assert_eq!(
        first.peer_compat.enforcement_height(),
        Some(ENFORCE_FROM),
        "the boot must read the height out of `ChainParams`"
    );
    assert!(first.peer_compat.on_declaration(peer, digest_before));
    assert_eq!(first.peer_compat.status(&peer), PeerCompat::Verified);
    assert!(
        first
            .peer_compat
            .may_participate_in_consensus(&peer, ENFORCE_FROM),
        "a verified peer participates above the height"
    );
    // Release the database lock: a "restart" that left a handle alive would be a
    // no-op that passed, because RocksDB refuses a directory whose lock is held.
    drop(first);

    // ── run 2, same directory, same genesis ─────────────────────────────────
    let second = boot(dir.path(), &genesis, secret);
    assert_eq!(
        second.protocol_digest, digest_before,
        "the same binary on the same genesis must declare the same digest across \
         a restart, or every peer would see a mismatch on every restart"
    );
    assert_eq!(
        second.peer_compat.status(&peer),
        PeerCompat::Undeclared,
        "the restarted node must have forgotten the declaration — it is held in \
         memory and persisted nowhere. If this ever starts passing as `Verified` \
         it means compatibility state became durable, and a peer could be trusted \
         across a restart on the strength of an answer given by a binary it is no \
         longer running"
    );
    assert!(
        !second
            .peer_compat
            .may_participate_in_consensus(&peer, ENFORCE_FROM),
        "and above the enforcement height, forgetting means REFUSED: the failure \
         direction on a restart is refusal, not admission"
    );
    assert!(
        second
            .peer_compat
            .may_participate_in_consensus(&peer, ENFORCE_FROM - 1),
        "below the height the restart changes nothing, because silence is \
         admitted there"
    );

    // The node re-asks on reconnect, the peer answers, and it is back.
    assert!(second
        .peer_compat
        .on_declaration(peer, second.protocol_digest));
    assert!(
        second
            .peer_compat
            .may_participate_in_consensus(&peer, ENFORCE_FROM),
        "one round trip after the restart the matching peer is admitted again"
    );
}

/// A restart does not rescue a peer that declared the WRONG digest.
///
/// The mirror of the test above, and the more dangerous direction: forgetting is
/// safe when it turns `Verified` into `Undeclared` above the height, because
/// both ends of that are refusal. It would NOT be safe if a mismatching peer
/// came back as merely undeclared on a chain still below its enforcement
/// height — it would be admitted. This test pins that the peer re-declares the
/// same mismatch and is refused again, and says plainly what the window is.
#[tokio::test]
async fn a_mismatching_peer_is_refused_again_after_a_restart() {
    let validator = KeyPair::generate();
    let funded = KeyPair::generate();
    let genesis = genesis_for(&validator, &funded);
    let secret = *validator.private_key().as_bytes();
    let dir = tempfile::TempDir::new().expect("temp dir");
    let peer = PeerId::random();
    let theirs = Hash::hash(b"a different binary's protocol digest");

    let first = boot(dir.path(), &genesis, secret);
    assert!(!first.peer_compat.on_declaration(peer, theirs));
    assert!(!first
        .peer_compat
        .may_participate_in_consensus(&peer, ENFORCE_FROM - 1));
    drop(first);

    let second = boot(dir.path(), &genesis, secret);
    // The window, stated rather than hidden: immediately after the restart the
    // node has forgotten the mismatch, so BELOW the enforcement height this peer
    // is admissible again until it answers. That is the same window every
    // undeclared peer occupies and it closes on the first round trip.
    assert_eq!(second.peer_compat.status(&peer), PeerCompat::Undeclared);
    assert!(second
        .peer_compat
        .may_participate_in_consensus(&peer, ENFORCE_FROM - 1));

    // It answers the same way its binary always will, and is refused again at
    // every height.
    assert!(!second.peer_compat.on_declaration(peer, theirs));
    assert_eq!(second.peer_compat.status(&peer), PeerCompat::Incompatible);
    for h in [0, ENFORCE_FROM - 1, ENFORCE_FROM, TIP] {
        assert!(
            !second.peer_compat.may_participate_in_consensus(&peer, h),
            "a mismatching peer must be refused at height {h} after a restart too"
        );
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// 5. The value this node puts on the wire
// ═════════════════════════════════════════════════════════════════════════════

/// The digest this node DECLARES, and compares every peer against, is the one
/// that moves when `MAX_BLOCK_WRITE_SET_BYTES` moves.
///
/// `crates/state/tests/protocol_digest_mismatched_binaries.rs` proves the
/// ceiling is folded by name and by value into
/// `sumchain_state::protocol_digest`. That is a claim about a function. This is
/// the claim that matters for the release condition: the function's output is
/// what `Node::with_rpc_config` stores in `Node::protocol_digest`, what it hands
/// `PeerCompatRegistry` as `ours`, and therefore what a peer has to match before
/// `admit_peer_block` will let its blocks near the engine.
///
/// Two nodes built with different ceilings would hold different values here, so
/// each would mark the other `Incompatible` on its first declaration — which is
/// what "covered by mandatory compatibility enforcement" has to mean.
///
/// The one link left to the source scan is the `NetworkEvent::ProtocolIdRequest`
/// arm answering with `digest: self.protocol_digest`; that arm is inside
/// `Node::run`.
#[tokio::test]
async fn the_digest_this_node_declares_covers_the_block_write_set_ceiling() {
    use sumchain_state::protocol_digest::{
        consensus_limits, protocol_digest, protocol_digest_with_limits, LimitValue,
    };

    let validator = KeyPair::generate();
    let funded = KeyPair::generate();
    let genesis = genesis_for(&validator, &funded);
    let dir = tempfile::TempDir::new().expect("temp dir");
    let node = boot(dir.path(), &genesis, *validator.private_key().as_bytes());

    assert_eq!(
        node.protocol_digest,
        protocol_digest(&genesis).expect("protocol digest"),
        "the node must declare `sumchain_state::protocol_digest` for its genesis \
         and not some other value"
    );
    assert_eq!(
        node.peer_compat.protocol_digest(),
        node.protocol_digest,
        "and must judge peers against the same value it declares, or it would \
         refuse peers that agree with it and admit peers that do not"
    );

    // The comparison a node built with a doubled ceiling would make against this
    // one. Same genesis file, same everything else.
    let doubled: Vec<(&'static str, LimitValue)> = consensus_limits()
        .into_iter()
        .map(|(n, v)| {
            if n == "MAX_BLOCK_WRITE_SET_BYTES" {
                (
                    n,
                    LimitValue::Num((sumchain_state::MAX_BLOCK_WRITE_SET_BYTES as u128) * 2),
                )
            } else {
                (n, v)
            }
        })
        .collect();
    let other_binary =
        protocol_digest_with_limits(&genesis, &doubled).expect("the other binary's digest");
    assert_ne!(
        other_binary, node.protocol_digest,
        "a node built with a doubled block write-set ceiling would declare the \
         same digest as this one, and the ceiling would not be covered by \
         enforcement at all"
    );

    // And that peer is refused — at every height, in both phases, which is what
    // makes the coverage MANDATORY rather than advisory.
    let peer = PeerId::random();
    assert!(
        !node.peer_compat.on_declaration(peer, other_binary),
        "a peer declaring the doubled-ceiling digest must be refused"
    );
    assert_eq!(node.peer_compat.status(&peer), PeerCompat::Incompatible);
    for h in [0, ENFORCE_FROM - 1, ENFORCE_FROM, TIP, u64::MAX] {
        assert!(
            !node.peer_compat.may_participate_in_consensus(&peer, h),
            "the doubled-ceiling peer must be refused at height {h}, below the \
             enforcement boundary as well as above it — a binary disagreement is \
             not a thing an operator gets to phase in"
        );
    }
}
