//! The activation checkpoint under REAL PoA fork choice, with several
//! validators, and the liveness half of the claim.
//!
//! Release blocker 9. Everything else about the checkpoint is proven on one
//! validator or below the engine: the arithmetic that bounds how long it binds,
//! the refusal at `stage_branch_unwind`, the refusal at `execute_reorg`, and one
//! depth-2 refusal through `import_block`. None of that says what a chain with a
//! rotating proposer does when several different competing branches arrive.
//!
//! Two things have to hold at once, and the second is the one that is easy to
//! lose while proving the first:
//!
//! * **Safety.** Every competing branch that reaches below the boundary is
//!   refused, and refused the SAME way each time — not once and then differently,
//!   and not depending on which validator produced it.
//! * **Liveness.** Honest progress does not halt. The node keeps importing and
//!   producing afterwards, a legitimate switch that stays above the boundary is
//!   still performed, and the chain advances.
//!
//! A refusal rule with no liveness evidence is indistinguishable from a node
//! that has simply stopped.

use std::collections::HashMap;
use std::sync::Arc;

use sumchain_consensus::{ConsensusEngine, PoAEngine};
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::{ChainParams, Genesis};
use sumchain_primitives::{Address, Block, SignedTransaction, Transaction};
use sumchain_state::{Mempool, MempoolConfig, StateManager};
use sumchain_storage::{cf, Database};
use tempfile::TempDir;

const CHAIN_ID: u64 = 1;
const VALIDATORS: usize = 3;

/// The height at and above which a generic journal is authoritative. Pinned, so
/// every node in every world agrees on it without observing its own history.
const BOUNDARY: u64 = 4;

/// One validator's node.
struct ValidatorNode {
    _dir: TempDir,
    db: Arc<Database>,
    mempool: Arc<Mempool>,
    consensus: Arc<PoAEngine>,
    pubkey: [u8; 32],
}

impl ValidatorNode {
    fn new(genesis: &Genesis, secret: [u8; 32]) -> Self {
        let key = KeyPair::from_bytes(secret);
        let pubkey = *key.public_key().as_bytes();
        let dir = TempDir::new().expect("temp dir");
        let db = Arc::new(Database::open_default(dir.path()).expect("open database"));
        let state = Arc::new(StateManager::new(db.clone(), CHAIN_ID));
        let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
        let consensus = Arc::new(
            PoAEngine::new(
                db.clone(),
                state.clone(),
                mempool.clone(),
                genesis,
                Some(key),
            )
            .expect("engine"),
        );
        consensus.init_genesis(genesis).expect("init genesis");
        Self {
            _dir: dir,
            db,
            mempool,
            consensus,
            pubkey,
        }
    }

    fn height(&self) -> u64 {
        self.consensus.current_height()
    }
}

/// A set of validators that agree with each other: every block one of them
/// produces is imported by the rest, so all of them hold the same chain.
///
/// This is what makes the test multi-validator rather than one node pretending.
/// `create_block` refuses unless `is_proposer(height)`, and the proposer rotates
/// `validators[height % N]`, so each block is produced by the validator whose
/// turn it actually is and the others accept it as an extension.
struct World {
    nodes: Vec<ValidatorNode>,
    /// Distinguishes this world's blocks from another's at the same height.
    fee: u128,
    chain: Vec<Block>,
}

impl World {
    fn new(genesis: &Genesis, secrets: &[[u8; 32]], fee: u128) -> Self {
        Self {
            nodes: secrets
                .iter()
                .map(|s| ValidatorNode::new(genesis, *s))
                .collect(),
            fee,
            chain: Vec::new(),
        }
    }

    /// The node whose validator is the proposer for the next height.
    fn proposer_index(&self, height: u64) -> usize {
        let expected = self.nodes[0].consensus.get_proposer(height);
        self.nodes
            .iter()
            .position(|n| n.pubkey == expected)
            .expect("the proposer must be one of this world's validators")
    }

    /// Produce the next block at its rightful proposer and import it everywhere
    /// else, so the whole world advances together.
    async fn advance(&mut self, sender: &KeyPair, to: Address, nonce: u64) -> Block {
        let height = self.nodes[0].height() + 1;
        let idx = self.proposer_index(height);
        let tx = transfer(sender, to, 1_000, self.fee, nonce);
        self.nodes[idx].mempool.add(tx).expect("mempool");
        let txs = self.nodes[idx].mempool.select_for_block(100);
        assert!(!txs.is_empty());
        let block = self.nodes[idx]
            .consensus
            .propose_block(txs)
            .await
            .expect("the rightful proposer produces");
        assert_eq!(block.height(), height);
        for (i, node) in self.nodes.iter().enumerate() {
            if i != idx {
                node.consensus
                    .import_block(block.clone())
                    .await
                    .expect("every other validator accepts an honest extension");
                assert_eq!(node.height(), height, "validator {i} must follow");
            }
        }
        self.chain.push(block.clone());
        block
    }

    fn head(&self) -> &Block {
        self.chain.last().expect("non-empty chain")
    }
}

fn transfer(from: &KeyPair, to: Address, amount: u128, fee: u128, nonce: u64) -> SignedTransaction {
    let tx = Transaction::new(CHAIN_ID, from.address(), to, amount, fee, nonce);
    let sig = sign(tx.signing_hash().as_bytes(), from.private_key());
    SignedTransaction::new(tx, *sig.as_bytes(), *from.public_key().as_bytes())
}

fn genesis_for(validators: &[KeyPair], funded: &[&KeyPair]) -> Genesis {
    let mut params = ChainParams::default();
    params.application_journal_enabled_from_height = Some(BOUNDARY);
    // Finality is put out of reach ON PURPOSE, and the reason is worth stating.
    //
    // `plan_reorg` refuses to walk at or below the finalized height, and it does
    // that BEFORE the activation checkpoint is consulted. On a chain with an
    // ordinary finality depth, finality is usually what refuses a deep crossing
    // switch, and the checkpoint never gets a turn — which is a fine thing to be
    // true in production and useless here, because a test that measures
    // finality's refusal has measured nothing about the checkpoint.
    //
    // So this fixture removes finality from the picture, leaving the checkpoint
    // as the only rule that can refuse. The corollary belongs in the report
    // rather than hidden here: the checkpoint's practical importance is confined
    // to the window where the activation boundary is DEEPER than finality, which
    // is exactly the window right after an upgrade.
    params.finality_depth = 1_000_000;
    let mut alloc: HashMap<String, u128> = validators
        .iter()
        .map(|v| (v.address().to_base58(), 100_000_000u128))
        .collect();
    for f in funded {
        alloc.insert(f.address().to_base58(), 100_000_000u128);
    }
    let g = Genesis::new(
        CHAIN_ID,
        0,
        validators
            .iter()
            .map(|v| v.public_key().to_base58())
            .collect(),
        alloc,
        params,
    );
    // Through the authoritative loader, so the pinned gate is one an operator
    // could actually ship.
    Genesis::from_json(&g.to_json().expect("serialize")).expect("a pinned gate must validate")
}

/// Every competing branch that reaches below the checkpoint is refused, the same
/// way each time — and the chain keeps going.
#[tokio::test]
async fn competing_pre_boundary_branches_are_refused_and_progress_continues() {
    let validators: Vec<KeyPair> = (0..VALIDATORS).map(|_| KeyPair::generate()).collect();
    let secrets: Vec<[u8; 32]> = validators
        .iter()
        .map(|v| *v.private_key().as_bytes())
        .collect();
    let alice = KeyPair::generate();
    let bob = KeyPair::generate();
    let genesis = genesis_for(&validators, &[&alice, &bob]);
    assert_eq!(
        genesis.validators.len(),
        VALIDATORS,
        "the proposer must rotate, or this is a one-validator test wearing a hat"
    );

    // The honest world, built by three validators taking turns up to height 5 —
    // one above the pinned boundary, so a branch forking at genesis crosses it.
    let mut honest = World::new(&genesis, &secrets, 10);
    for n in 0..5u64 {
        honest.advance(&alice, bob.address(), n).await;
    }
    assert_eq!(honest.head().height(), 5);
    let honest_head = honest.head().clone();
    assert_eq!(honest.nodes[0].height(), 5);

    // The proposer really did rotate, or the fork choice under test is not PoA's.
    let proposers: std::collections::BTreeSet<[u8; 32]> = honest
        .chain
        .iter()
        .map(|b| b.header.proposer_pubkey)
        .collect();
    assert!(
        proposers.len() >= 2,
        "at least two distinct validators must have produced blocks: {}",
        proposers.len()
    );

    // Several DIFFERENT competing worlds, each a full three-validator chain
    // forked from genesis, each reaching height 6 so longest-chain fork choice
    // wants it. Every one of them abandons heights 1..=5, which spans the
    // boundary at 4.
    let mut refusals = Vec::new();
    for (world_index, fee) in [21u128, 37, 53].into_iter().enumerate() {
        let node = &honest.nodes[0];
        let mut rival = World::new(&genesis, &secrets, fee);
        for n in 0..6u64 {
            rival.advance(&alice, bob.address(), n).await;
        }
        assert_eq!(rival.head().height(), 6);
        assert_ne!(
            rival.chain[0].hash(),
            honest.chain[0].hash(),
            "world {world_index} must really be a different branch"
        );

        // The rival branch arrives block by block, as it would over the network.
        // A block shorter than the honest head loses fork choice and is archived
        // without publishing; one that ties at height 5 or exceeds it at 6 wins
        // and takes the reorg arm. WHICH of those two wins depends on a hash
        // comparison, so this does not assume — it imports the whole branch and
        // requires that every switch attempted was refused, and that no import
        // at all moved the head.
        let mut world_refusals = Vec::new();
        for block in &rival.chain {
            match node.consensus.import_block(block.clone()).await {
                Ok(()) => {}
                Err(e) => world_refusals.push(e.to_string()),
            }
            assert_eq!(
                node.height(),
                5,
                "world {world_index}: no import of a rival block may move the head — a \
                 losing one is archived and a winning one is refused"
            );
        }
        assert!(
            !world_refusals.is_empty(),
            "world {world_index}: fork choice must have wanted at least one of these \
             blocks, or this branch never reached the reorg arm and proves nothing"
        );
        for r in &world_refusals {
            assert_eq!(
                r, &world_refusals[0],
                "world {world_index}: every refusal on one branch must be the same one"
            );
        }
        refusals.push(world_refusals.remove(0));

        // Refused, and nothing moved: same head, same canonical height index.
        assert_eq!(node.height(), 5);
        assert_eq!(
            node.consensus.best_block_hash(),
            honest_head.hash(),
            "world {world_index}: the node must stay on the honest branch"
        );
        for h in 1..=5u64 {
            assert_eq!(
                node.consensus.get_block_by_height(h).map(|b| b.hash()),
                Some(honest.chain[(h - 1) as usize].hash()),
                "world {world_index}: height {h} must still name the honest block"
            );
        }
    }

    // CONSISTENTLY: three distinct rival branches, three identical refusals.
    assert_eq!(refusals.len(), 3);
    for r in &refusals {
        assert_eq!(
            r, &refusals[0],
            "the same condition must produce the same refusal, whichever branch \
             and whichever validator produced it"
        );
        assert!(
            r.contains("refusing a 5-block switch") && r.contains("only 2 block(s)"),
            "{r}"
        );
    }

    // ── LIVENESS ────────────────────────────────────────────────────────────
    //
    // The node is not wedged. It still imports honest extensions, it still
    // produces when its own turn comes, and the rest of the validator set
    // follows it.
    for n in 5..9u64 {
        honest.advance(&alice, bob.address(), n).await;
    }
    assert_eq!(
        honest.head().height(),
        9,
        "the chain advanced after the refusals"
    );
    for (i, n) in honest.nodes.iter().enumerate() {
        assert_eq!(n.height(), 9, "validator {i} must still be following");
        assert_eq!(n.consensus.best_block_hash(), honest.head().hash());
    }
    assert!(
        honest
            .chain
            .iter()
            .skip(5)
            .any(|b| b.header.proposer_pubkey == *validators[0].public_key().as_bytes()),
        "the node that did the refusing must itself have produced afterwards"
    );

    // And every block it published has a journal, including the ones produced
    // after the refusals — the write side is ungated, so refusing a switch does
    // not interrupt the record.
    let node = &honest.nodes[0];
    for block in &honest.chain {
        assert!(
            node.db
                .get(
                    cf::APPLICATION_JOURNAL,
                    &sumchain_storage::schema::journal_key(block.height(), &block.hash()),
                )
                .expect("read")
                .is_some(),
            "height {} must be journalled",
            block.height()
        );
    }
}

/// A legitimate switch that stays at or above the boundary is still PERFORMED,
/// under the same multi-validator fork choice.
///
/// Without this, "the checkpoint refuses crossing branches" and "the node
/// refuses everything" are the same observation.
#[tokio::test]
async fn a_switch_above_the_boundary_is_still_performed_with_several_validators() {
    let validators: Vec<KeyPair> = (0..VALIDATORS).map(|_| KeyPair::generate()).collect();
    let secrets: Vec<[u8; 32]> = validators
        .iter()
        .map(|v| *v.private_key().as_bytes())
        .collect();
    let alice = KeyPair::generate();
    let bob = KeyPair::generate();
    let genesis = genesis_for(&validators, &[&alice, &bob]);

    // A shared prefix up to the boundary, built by the rotating proposer. Both
    // worlds build it from the same transactions, so the blocks agree.
    let mut honest = World::new(&genesis, &secrets, 10);
    for n in 0..BOUNDARY {
        honest.advance(&alice, bob.address(), n).await;
    }
    assert_eq!(honest.nodes[0].height(), BOUNDARY);
    let fork_point = honest.head().clone();

    // The honest branch continues one block past the boundary.
    honest.advance(&alice, bob.address(), BOUNDARY).await;
    assert_eq!(honest.nodes[0].height(), BOUNDARY + 1);
    let abandoned = honest.head().clone();

    // A rival that forks AT the fork point and goes two blocks further. Built on
    // a second world seeded from the same prefix, by importing it.
    let mut rival = World::new(&genesis, &secrets, 44);
    for block in &honest.chain[..BOUNDARY as usize] {
        for n in &rival.nodes {
            n.consensus
                .import_block(block.clone())
                .await
                .expect("the rival world adopts the shared prefix");
        }
        rival.chain.push(block.clone());
    }
    assert_eq!(rival.head().hash(), fork_point.hash());
    for n in BOUNDARY..BOUNDARY + 2 {
        rival.advance(&alice, bob.address(), n).await;
    }
    assert_eq!(rival.head().height(), BOUNDARY + 2);

    // It arrives. The abandoned branch is ONE block, at a height at or above the
    // boundary, so nothing crosses and the switch is performed.
    let node = &honest.nodes[0];
    let first_rival = rival.chain[BOUNDARY as usize].clone();
    node.consensus
        .import_block(first_rival)
        .await
        .expect("a sibling at the boundary is archived or adopted, not refused");
    node.consensus
        .import_block(rival.head().clone())
        .await
        .expect("a switch wholly at or above the boundary must be PERFORMED");

    assert_eq!(
        node.height(),
        BOUNDARY + 2,
        "the node adopted the rival branch"
    );
    assert_eq!(node.consensus.best_block_hash(), rival.head().hash());
    assert_ne!(
        node.consensus
            .get_block_by_height(BOUNDARY + 1)
            .map(|b| b.hash()),
        Some(abandoned.hash()),
        "the abandoned block must no longer be canonical at its height"
    );
}
