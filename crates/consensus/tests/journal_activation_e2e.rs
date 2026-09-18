//! A PINNED application-journal activation height, driven end to end.
//!
//! Release blocker 4. `ChainParams::application_journal_enabled_from_height`
//! had a tested translation site (`ActivationSource::from_configured_height`)
//! and a tested classification (`ActivatedJournal`), but the live path was only
//! ever exercised with the OBSERVED boundary. A configuration field that is
//! never driven through the engine is a field nobody has shown works.
//!
//! What is driven here, in one process, on real databases:
//!
//! * **Configuration loading.** The height arrives as JSON, through
//!   `Genesis::from_json`, and through `ChainParams::validate`.
//! * **`PoAEngine`.** The engine is constructed from that genesis and produces
//!   real blocks through `propose_block`.
//! * **Publication.** Every block at and above the pinned height leaves a
//!   decodable generic journal on disk, keyed by its own `(height, hash)`.
//! * **Restart.** The engine is dropped, the database reopened, the startup
//!   format gate re-run, and a second engine built from the same genesis.
//!   The pinned value is CONFIGURATION, not state, so it has to survive by
//!   being read again rather than by having been stored.
//! * **Reorg.** A sibling branch is imported and the engine switches to it —
//!   and the pinned height decides whether a missing record halts that switch
//!   or is tolerated as pre-journal history. That difference is the only
//!   engine-visible proof that the configured number reached the reorg path.

use std::collections::HashMap;
use std::sync::Arc;

use sumchain_consensus::{ConsensusEngine, PoAEngine};
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::{ChainParams, Genesis};
use sumchain_primitives::{Address, Block, Hash, SignedTransaction, Transaction};
use sumchain_state::{Mempool, MempoolConfig, StateManager};
use sumchain_storage::journal::{
    ActivationSource, ApplicationJournal, JournalActivation, JournalRequirement,
};
use sumchain_storage::{cf, Database};
use tempfile::TempDir;

const CHAIN_ID: u64 = 1;

/// Bounded retry budget for arranging `hash(B) < hash(A)`, which is exactly
/// `LongestChainForkChoice::should_switch` at equal height. Same device as the
/// issue-#253 probe, and bounded for the same reason.
const MAX_ATTEMPTS: usize = 24;

/// A node whose data directory outlives its engine, so it can be restarted.
struct E2ENode {
    dir: TempDir,
    db: Arc<Database>,
    state: Arc<StateManager>,
    mempool: Arc<Mempool>,
    consensus: Arc<PoAEngine>,
    genesis: Genesis,
    validator: [u8; 32],
}

impl E2ENode {
    fn new(genesis: &Genesis, validator: [u8; 32]) -> Self {
        let dir = TempDir::new().expect("temp dir");
        let mut node = Self::open(dir, genesis, validator);
        node.consensus.init_genesis(genesis).expect("init genesis");
        node.started_clean();
        node
    }

    fn open(dir: TempDir, genesis: &Genesis, validator: [u8; 32]) -> Self {
        let db = Arc::new(Database::open_default(dir.path()).expect("open database"));
        let state = Arc::new(StateManager::new(db.clone(), CHAIN_ID));
        let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
        let consensus = Arc::new(
            PoAEngine::new(
                db.clone(),
                state.clone(),
                mempool.clone(),
                genesis,
                Some(KeyPair::from_bytes(validator)),
            )
            .expect("create consensus engine"),
        );
        Self {
            dir,
            db,
            state,
            mempool,
            consensus,
            genesis: genesis.clone(),
            validator,
        }
    }

    /// The startup gate the node runs before anything else, run here too, so a
    /// restart in this test is the same act a restart in production is.
    fn started_clean(&self) {
        sumchain_storage::journal::validate_startup(&self.db).expect("journal startup gate");
        self.genesis
            .params
            .validate()
            .expect("chain params must be self-consistent at startup");
    }

    /// Drop the engine, close the database, reopen the same directory, and
    /// build a new engine from the same genesis document.
    fn restart(self) -> Self {
        let E2ENode {
            dir,
            db,
            state,
            mempool,
            consensus,
            genesis,
            validator,
        } = self;
        drop(consensus);
        drop(mempool);
        drop(state);
        drop(db);
        let node = Self::open(dir, &genesis, validator);
        node.started_clean();
        // What the real boot sequence does after constructing the engine: the
        // head comes off disk, not out of the constructor.
        node.consensus
            .load_chain()
            .expect("load the chain from storage")
            .expect("a restarted node must find its own head");
        node
    }

    fn submit(&self, tx: SignedTransaction) {
        self.mempool.add(tx).expect("mempool accepts tx");
    }

    async fn produce(&self) -> Block {
        let txs = self.mempool.select_for_block(100);
        assert!(!txs.is_empty(), "this fixture produces non-empty blocks");
        self.consensus
            .propose_block(txs)
            .await
            .expect("propose block")
    }

    fn head_height(&self) -> u64 {
        self.consensus.current_height()
    }

    fn balance(&self, addr: &Address) -> u128 {
        self.state.get_balance(addr).unwrap_or(0)
    }

    /// The pinned activation this node's OWN configuration resolves to.
    fn activation(&self) -> JournalActivation {
        JournalActivation::resolve(
            &self.db,
            ActivationSource::from_configured_height(
                self.genesis.params.application_journal_enabled_from_height,
            ),
        )
        .expect("resolve activation")
    }

    fn journal_row(&self, height: u64, hash: &Hash) -> Option<Vec<u8>> {
        self.db
            .get(
                cf::APPLICATION_JOURNAL,
                &sumchain_storage::schema::journal_key(height, hash),
            )
            .expect("read the journal column family")
    }

    fn genesis_block(&self) -> Block {
        self.consensus
            .get_block_by_height(0)
            .expect("genesis block present")
    }
}

fn transfer(from: &KeyPair, to: Address, amount: u128, fee: u128, nonce: u64) -> SignedTransaction {
    let tx = Transaction::new(CHAIN_ID, from.address(), to, amount, fee, nonce);
    let sig = sign(tx.signing_hash().as_bytes(), from.private_key());
    SignedTransaction::new(tx, *sig.as_bytes(), *from.public_key().as_bytes())
}

/// Genesis as a DOCUMENT, with the gate written into the JSON rather than poked
/// into a struct. This is the leg that says an operator can express the height
/// at all: a field that only exists in Rust is not a deployment surface.
fn genesis_json_with_pinned_gate(
    validator: &KeyPair,
    alloc: &[(&KeyPair, u128)],
    pinned: Option<u64>,
    account_root: Option<u64>,
) -> Genesis {
    let mut params = ChainParams::default();
    params.application_journal_enabled_from_height = pinned;
    params.account_root_enabled_from_height = account_root;
    let genesis = Genesis::new(
        CHAIN_ID,
        0,
        vec![validator.public_key().to_base58()],
        alloc
            .iter()
            .map(|(k, v)| (k.address().to_base58(), *v))
            .collect::<HashMap<_, _>>(),
        params,
    );
    let json = genesis.to_json().expect("serialize genesis");
    assert!(
        json.contains("application_journal_enabled_from_height"),
        "the gate must be present in the genesis document, not only in the struct"
    );
    // Through the authoritative loader, which validates.
    Genesis::from_json(&json).expect("a pinned journal gate must load and validate")
}

// ─────────────────────────────────────────────────────────────────────────────

/// A pinned height is accepted by the loader and by the engine, journals are
/// written at and above it, and the pin survives a restart.
#[tokio::test]
async fn a_pinned_activation_height_is_accepted_and_journals_are_written_from_it() {
    const PINNED: u64 = 2;

    let validator = KeyPair::generate();
    let alice = KeyPair::generate();
    let bob = KeyPair::generate();
    let genesis = genesis_json_with_pinned_gate(
        &validator,
        &[
            (&validator, 100_000_000),
            (&alice, 10_000_000),
            (&bob, 10_000_000),
        ],
        Some(PINNED),
        // The account commitment may open at or after the journal boundary, and
        // this fixture opens it exactly there — the tightest legal pair, and the
        // one the ordering invariant exists to permit.
        Some(PINNED),
    );
    assert_eq!(
        genesis.params.application_journal_enabled_from_height,
        Some(PINNED),
        "the pinned height must survive the JSON round trip"
    );

    let node = E2ENode::new(&genesis, *validator.private_key().as_bytes());

    // Three blocks, straddling the pinned height.
    let mut published = Vec::new();
    for n in 0..3u64 {
        node.submit(transfer(&alice, bob.address(), 1_000, 10, n));
        published.push(node.produce().await);
    }
    assert_eq!(node.head_height(), 3);

    // The pin, as the ENGINE resolves it from its own params.
    let activation = node.activation();
    assert_eq!(
        activation.source(),
        ActivationSource::Pinned(PINNED),
        "the configured height must reach the engine as a pin, not as an observation"
    );
    assert_eq!(activation.boundary(), Some(PINNED));
    assert_eq!(
        activation.requirement_at(PINNED - 1),
        JournalRequirement::PreActivation
    );
    assert_eq!(
        activation.requirement_at(PINNED),
        JournalRequirement::Required
    );

    // MANDATORY from the pinned height: every block at or above it has a record
    // on disk that decodes under its own `(height, hash)`. The write side is
    // ungated, so the record at height 1 is there too — asserted rather than
    // glossed, because "written everywhere" and "required from PINNED" are two
    // different claims and only the second is the gate's.
    for block in &published {
        let raw = node
            .journal_row(block.height(), &block.hash())
            .unwrap_or_else(|| panic!("no journal row at height {}", block.height()));
        let decoded = ApplicationJournal::decode_for(&raw, block.height(), &block.hash())
            .expect("the record must decode under the key it was filed at");
        assert_eq!(decoded.height(), block.height());
        assert_eq!(decoded.block_hash(), block.hash());
        assert!(
            !decoded.is_empty(),
            "a block carrying a transfer must journal the rows it wrote"
        );
    }

    // The observed boundary is 1 — `init_genesis` writes no record for genesis —
    // so the pin is a DIFFERENT number from the one this database would have
    // observed. Without that, the two would be indistinguishable here.
    let observed =
        JournalActivation::resolve(&node.db, ActivationSource::ObservedFromChain).expect("observe");
    assert_eq!(observed.boundary(), Some(1));
    assert_ne!(
        observed.boundary(),
        activation.boundary(),
        "the fixture must distinguish the pinned boundary from the observed one, or it \
         proves nothing about the pin"
    );

    // ── restart ─────────────────────────────────────────────────────────────
    let alice_before = node.balance(&alice.address());
    let node = node.restart();
    assert_eq!(node.head_height(), 3, "the chain survives the restart");
    assert_eq!(node.balance(&alice.address()), alice_before);
    assert_eq!(
        node.activation().source(),
        ActivationSource::Pinned(PINNED),
        "the pin is configuration and must be re-read, not recovered from the database"
    );

    // And a block produced AFTER the restart is journalled the same way.
    node.submit(transfer(&alice, bob.address(), 1_000, 10, 3));
    let after = node.produce().await;
    assert_eq!(after.height(), 4);
    let raw = node
        .journal_row(after.height(), &after.hash())
        .expect("a post-restart block must be journalled too");
    ApplicationJournal::decode_for(&raw, after.height(), &after.hash()).expect("decodes");
}

/// The pinned height is what the REORG path reads, proven by the only thing
/// that can prove it: two runs of the same switch, differing in the configured
/// number alone, reaching two different outcomes.
///
/// Both runs delete the generic record for the block being abandoned. With the
/// boundary pinned AT that height the record is mandatory and the switch must
/// HALT; with it pinned ABOVE, the block is pre-journal history, the legacy
/// per-subsystem diffs are the fallback, and the switch proceeds.
///
/// Nothing else differs — same genesis except that one field, same validator,
/// same transactions, same fork.
#[tokio::test]
async fn the_pinned_height_decides_whether_a_reorg_halts_or_falls_back() {
    for (pinned, must_halt) in [(1u64, true), (5u64, false)] {
        let mut settled = false;
        for attempt in 0..MAX_ATTEMPTS {
            let fee_b = 20u128 + attempt as u128;

            let validator = KeyPair::generate();
            let alice = KeyPair::generate();
            let bob = KeyPair::generate();
            let carol = KeyPair::generate();
            let dave = KeyPair::generate();
            let genesis = genesis_json_with_pinned_gate(
                &validator,
                &[
                    (&validator, 100_000_000),
                    (&alice, 10_000_000),
                    (&bob, 10_000_000),
                ],
                Some(pinned),
                None,
            );
            let vk = *validator.private_key().as_bytes();
            let node_a = E2ENode::new(&genesis, vk);
            let node_b = E2ENode::new(&genesis, vk);
            assert_eq!(
                node_a.genesis_block().hash(),
                node_b.genesis_block().hash(),
                "A and B must share a byte-identical genesis, else there is no ancestor"
            );

            node_a.submit(transfer(&alice, carol.address(), 1_000, 10, 0));
            node_b.submit(transfer(&bob, dave.address(), 2_000, fee_b, 0));
            let block_a = node_a.produce().await;
            let block_b = node_b.produce().await;
            assert_eq!(block_a.height(), 1);
            assert_eq!(block_b.height(), 1);
            if block_b.hash() >= block_a.hash() {
                continue; // fork choice would not switch; retry with a new fee
            }
            settled = true;

            // The abandoned branch is exactly [height 1], so it never crosses a
            // boundary in either configuration — what is under test is the
            // MISSING-record rule, not the checkpoint.
            assert!(
                node_a.journal_row(1, &block_a.hash()).is_some(),
                "A must have journalled its own block before the record is removed"
            );
            node_a
                .db
                .delete(
                    cf::APPLICATION_JOURNAL,
                    &sumchain_storage::schema::journal_key(1, &block_a.hash()),
                )
                .expect("remove the generic record for the block A is about to abandon");

            let alice_on_a = node_a.balance(&alice.address());
            let result = node_a.consensus.import_block(block_b.clone()).await;

            if must_halt {
                let err = result.expect_err(
                    "with the boundary pinned at the abandoned block's height, its missing \
                     record must halt the switch",
                );
                let rendered = err.to_string();
                assert!(
                    rendered.contains("no application journal for block")
                        || rendered.contains("undo journal"),
                    "the halt must name the missing record: {rendered}"
                );
                assert_eq!(
                    node_a.head_height(),
                    1,
                    "a halted switch leaves the node on the branch it was on"
                );
                assert_eq!(
                    node_a.balance(&alice.address()),
                    alice_on_a,
                    "and writes nothing"
                );
            } else {
                result.expect(
                    "with the boundary pinned above the branch, the block is pre-journal \
                     history and the legacy diffs are the fallback",
                );
                assert_eq!(
                    node_a.head_height(),
                    1,
                    "the switch adopted B's height-1 block"
                );
                assert_eq!(
                    node_a.consensus.get_block_by_height(1).map(|b| b.hash()),
                    Some(block_b.hash()),
                    "the adopted block must be B's, not A's"
                );
            }
            break;
        }
        assert!(
            settled,
            "could not arrange hash(B) < hash(A) in {MAX_ATTEMPTS} attempts for pin {pinned}"
        );
    }
}
