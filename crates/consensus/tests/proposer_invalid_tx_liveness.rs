//! One transaction that cannot execute must not stop a validator producing
//! blocks — and must not take honest traffic with it when it is removed.
//!
//! # The halt
//!
//! `execute_block`'s transaction loop ends in `Err(e) => return Err(e)`. Most
//! ways a transaction can fail are receipts — a bad nonce, a bad signature, an
//! empty balance, a subsystem's own semantic refusal — and a block carrying one
//! is still a block. But a handful of paths `?` a `StateError` straight out of
//! the dispatch arm, and each one of those makes the WHOLE BLOCK unexecutable.
//!
//! `PoAEngine::create_block` then returns that error, `run_block_producer` logs
//! "Failed to create block", and `mempool.remove_batch` — which is on the
//! success path only — is never reached. `Mempool::select_for_block` is
//! non-destructive and ordered by FEE, so the transaction is still there on the
//! next tick, sorted to the front, and is selected first again. Not a lost
//! slot: a validator that never produces another block. It costs one `min_fee`
//! and anyone can pay it.
//!
//! # Why "evict whatever failed" is the wrong repair
//!
//! The transactions that reach that arm are not one population. Three kinds
//! arrive there and they want three different answers:
//!
//!   * PERMANENTLY INVALID — `PolicyAccount { ModifyMembership }` is refused by
//!     `PolicyAccountExecutor::execute` on the operation code alone, before it
//!     reads any state. No height and no state makes it succeed. Evict it.
//!   * TEMPORARILY INELIGIBLE — an NFT `Mint` naming a collection that does not
//!     exist yet is `Err(BlockValidation("Collection not found"))`, and the
//!     very next block may contain the `CreateCollection` that makes it valid.
//!     Evicting it destroys a transaction whose only fault is arriving early.
//!   * TOO BIG FOR THIS BLOCK — a transaction that crosses
//!     `MAX_BLOCK_WRITE_SET_BYTES` at index 7 crossed it because the six before
//!     it spent the budget. Alone at the head of the next block it fits.
//!
//! So the file asserts both halves of the property, and the second half is the
//! one a careless fix breaks.

#![cfg(test)]

use std::collections::HashMap;
use std::sync::Arc;

use sumchain_consensus::{ConsensusEngine, PoAEngine};
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::{ChainParams, Genesis};
use sumchain_primitives::{
    Address, NftOperation, NftTxData, PolicyAccountOperation, PolicyAccountTxData,
    SignedTransaction, TransactionV2, TxPayload,
};
use sumchain_state::{Mempool, MempoolConfig, StateManager};
use sumchain_storage::Database;
use tempfile::TempDir;

const CHAIN_ID: u64 = 1;

fn params() -> ChainParams {
    ChainParams::with_v2_enabled()
}

struct Node {
    db: Arc<Database>,
    mempool: Arc<Mempool>,
    consensus: Arc<PoAEngine>,
    _dir: TempDir,
}

impl Node {
    fn new(genesis: &Genesis, key: [u8; 32]) -> Self {
        let dir = TempDir::new().expect("temp dir");
        let db = Arc::new(Database::open_default(dir.path()).expect("open database"));
        let state = Arc::new(StateManager::new(db.clone(), CHAIN_ID));
        let mempool = Arc::new(Mempool::new(MempoolConfig {
            max_per_sender: 10_000,
            ..MempoolConfig::default()
        }));
        let consensus = Arc::new(
            PoAEngine::new(
                db.clone(),
                state.clone(),
                mempool.clone(),
                genesis,
                Some(KeyPair::from_bytes(key)),
            )
            .expect("engine"),
        );
        consensus.init_genesis(genesis).expect("init genesis");
        Self {
            db,
            mempool,
            consensus,
            _dir: dir,
        }
    }

    /// One production tick, exactly as `run_block_producer` does it: select
    /// from the mempool by fee, hand the selection to `create_block`.
    async fn tick(&self) -> sumchain_consensus::Result<sumchain_primitives::Block> {
        let txs = self.mempool.select_for_block(1_000);
        self.consensus.propose_block(txs).await
    }
}

fn sign_v2(kp: &KeyPair, t: TransactionV2) -> SignedTransaction {
    let sig = sign(t.signing_hash().as_bytes(), kp.private_key());
    SignedTransaction::new_v2(t, *sig.as_bytes(), *kp.public_key().as_bytes())
}

/// PERMANENTLY INVALID. `PolicyAccountExecutor::execute` matches on the
/// operation code and returns `Err(StateError::InvalidOperation)` for
/// `ModifyMembership` before touching any state: the operation is reachable
/// only through `ExecuteProposal`, so a directly submitted one can never
/// succeed, at any height, against any state.
fn modify_membership_tx(kp: &KeyPair, nonce: u64, fee: u128) -> SignedTransaction {
    sign_v2(
        kp,
        TransactionV2 {
            chain_id: CHAIN_ID,
            from: kp.address(),
            fee,
            nonce,
            payload: TxPayload::PolicyAccount(PolicyAccountTxData {
                operation: PolicyAccountOperation::ModifyMembership,
                data: Vec::new(),
                recipient: Address::ZERO,
            }),
        },
    )
}

/// TEMPORARILY INELIGIBLE. An NFT mint against a collection id that nothing has
/// created yet. `NftExecutor` returns `Err(BlockValidation("Collection not
/// found"))` rather than a failed receipt, so it aborts the block the same way
/// — but a `CreateCollection` in a later block makes exactly this transaction
/// valid, so destroying it is destroying honest traffic.
fn mint_absent_collection_tx(kp: &KeyPair, nonce: u64, fee: u128) -> SignedTransaction {
    #[derive(serde::Serialize)]
    struct MintData {
        to: Address,
        metadata: Vec<u8>,
        uri_type: String,
        uri_value: Option<String>,
    }
    sign_v2(
        kp,
        TransactionV2 {
            chain_id: CHAIN_ID,
            from: kp.address(),
            fee,
            nonce,
            payload: TxPayload::Nft(NftTxData {
                collection_id: [0x55u8; 32],
                token_id: 0,
                operation: NftOperation::Mint,
                data: bincode::serialize(&MintData {
                    to: kp.address(),
                    metadata: Vec::new(),
                    uri_type: "onchain".to_string(),
                    uri_value: None,
                })
                .unwrap(),
            }),
        },
    )
}

fn transfer_tx(kp: &KeyPair, to: Address, nonce: u64, fee: u128) -> SignedTransaction {
    sign_v2(
        kp,
        TransactionV2 {
            chain_id: CHAIN_ID,
            from: kp.address(),
            fee,
            nonce,
            payload: TxPayload::Transfer { to, amount: 1 },
        },
    )
}

struct Fixture {
    genesis: Genesis,
    key: [u8; 32],
    /// The attacker, who pays one high fee and nothing else.
    attacker: KeyPair,
    /// Honest traffic, from a different sender so that no nonce sequence links
    /// the two populations.
    honest: KeyPair,
    sink: Address,
}

fn fixture() -> Fixture {
    let validator = KeyPair::generate();
    let attacker = KeyPair::generate();
    let honest = KeyPair::generate();
    let genesis = Genesis::new(
        CHAIN_ID,
        0,
        vec![validator.public_key().to_base58()],
        HashMap::from([
            (validator.address().to_base58(), 100_000_000u128),
            (attacker.address().to_base58(), 1_000_000_000_000u128),
            (honest.address().to_base58(), 1_000_000_000_000u128),
        ]),
        params(),
    );
    Fixture {
        genesis,
        key: *validator.private_key().as_bytes(),
        attacker,
        honest,
        sink: Address::new([0xAB; 20]),
    }
}

// ── 1. The reproduction ─────────────────────────────────────────────────────

/// One `ModifyMembership` transaction, at the highest fee in the mempool,
/// alongside eight ordinary transfers.
///
/// Before the fix: `create_block` returns `Err`, no block exists, nothing is
/// removed from the mempool, and every subsequent tick selects the same
/// transaction first and fails identically. This asserts the property the owner
/// stated — a block gets produced, and it CARRIES the later valid transactions.
#[tokio::test]
async fn a_permanently_invalid_high_fee_transaction_does_not_halt_the_proposer() {
    let f = fixture();
    let node = Node::new(&f.genesis, f.key);

    // Highest fee in the pool, so `select_for_block` puts it at index 0 on
    // every tick for as long as it is there.
    let poison = modify_membership_tx(&f.attacker, 0, 9_000_000);
    node.mempool.add(poison.clone()).ok();
    let honest: Vec<SignedTransaction> = (0..8)
        .map(|n| transfer_tx(&f.honest, f.sink, n, 1_000))
        .collect();
    for tx in &honest {
        node.mempool.add(tx.clone()).expect("admitted");
    }

    let block = node.tick().await.expect(
        "a validator must produce a block. An Err here is the permanent halt: \
         nothing is produced, nothing is evicted, and the next tick selects the \
         same transaction first and fails the same way, forever",
    );

    let carried: std::collections::HashSet<_> =
        block.transactions.iter().map(|t| t.hash()).collect();
    println!(
        "LIVENESS: block {} at height {} carried {} of 8 honest transfers",
        block.hash(),
        block.height(),
        honest.iter().filter(|t| carried.contains(&t.hash())).count()
    );
    assert!(
        honest.iter().all(|t| carried.contains(&t.hash())),
        "and it must carry the LATER VALID transactions — a block that is \
         produced empty every tick is a chain that advances while no \
         transaction ever confirms"
    );
    assert!(
        !node.mempool.contains(&poison.hash()),
        "the permanently invalid transaction must be gone from the mempool. \
         Left there it is selected first on the very next tick, at this fee"
    );
}

// ── 2. Across many ticks ────────────────────────────────────────────────────

/// Ten consecutive ticks, each with a fresh top-fee poison transaction.
///
/// A fix that survives one tick and not the next is not a fix: the halt is a
/// property of the repeated selection, not of any single proposal.
#[tokio::test]
async fn repeated_poisoning_over_many_ticks_never_stops_the_chain() {
    let f = fixture();
    let node = Node::new(&f.genesis, f.key);
    let mut nonce = 0u64;

    for tick in 0..10u64 {
        node.mempool
            .add(modify_membership_tx(&f.attacker, tick, 9_000_000))
            .ok();
        let tx = transfer_tx(&f.honest, f.sink, nonce, 1_000);
        node.mempool.add(tx.clone()).expect("admitted");

        let block = node
            .tick()
            .await
            .unwrap_or_else(|e| panic!("tick {tick} produced no block: {e}"));
        assert_eq!(block.height(), tick + 1, "the chain advanced at tick {tick}");
        assert!(
            block.transactions.iter().any(|t| t.hash() == tx.hash()),
            "tick {tick} must carry the honest transfer, not merely advance"
        );
        nonce += 1;
    }
    println!("TICKS: ten consecutive blocks, each carrying its honest transfer");
}

// ── 3. The half a careless fix breaks ───────────────────────────────────────

/// A transaction that is merely EARLY is not destroyed.
///
/// The NFT mint names a collection that does not exist yet. That aborts the
/// block exactly as the permanently invalid transaction does, and a fix that
/// evicts everything which fails execution would throw it away. It must instead
/// still be in the mempool afterwards, and must succeed once the collection
/// exists.
#[tokio::test]
async fn a_temporarily_ineligible_transaction_is_not_destroyed() {
    let f = fixture();
    let node = Node::new(&f.genesis, f.key);

    let early = mint_absent_collection_tx(&f.attacker, 0, 9_000_000);
    node.mempool.add(early.clone()).expect("admitted");
    let tx = transfer_tx(&f.honest, f.sink, 0, 1_000);
    node.mempool.add(tx.clone()).expect("admitted");

    let block = node.tick().await.expect("a block is still produced");
    println!(
        "QUARANTINE: block {} carried {} tx; early mint still pending: {}",
        block.hash(),
        block.tx_count(),
        node.mempool.contains(&early.hash())
    );
    assert!(
        block.transactions.iter().any(|t| t.hash() == tx.hash()),
        "the honest transfer behind it is carried"
    );
    assert!(
        node.mempool.contains(&early.hash()),
        "a transaction whose only fault is that its collection does not exist \
         YET must still be in the mempool: the block after this one may create \
         it. Evicting it satisfies the liveness half of the property by \
         destroying honest traffic, which is the failure the owner named"
    );
    let held = node.mempool.get(&early.hash()).expect("still held");
    assert_eq!(held.fee(), early.fee(), "and its fee was not rewritten");
    assert_eq!(held.nonce(), early.nonce(), "nor its nonce");
    assert_eq!(held.hash(), early.hash(), "nor any other byte of it");
}
