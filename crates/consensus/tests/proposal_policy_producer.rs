//! The producer applies the inclusion policy to whatever list it is handed.
//!
//! `run_block_producer` offers `select_for_block`'s output, which the pool has
//! already screened; `ConsensusEngine::propose_block` offers a caller's list,
//! which nothing has. `PoAEngine::create_block` screens both, so a block this
//! node produces carries only what its policy admits whichever way the
//! transactions arrived. The pool-level tests never reach `create_block`, so
//! without this test that screen could be removed and everything else would
//! stay green.

use std::collections::HashMap;
use std::sync::Arc;

use sumchain_consensus::{ConsensusEngine, PoAEngine};
use sumchain_crypto::{recipient_hash, sign, KeyPair};
use sumchain_genesis::{ChainParams, Genesis};
use sumchain_primitives::messaging::{
    ContentType, MessageFlags, MessageHeader, MessagingTxData, SRC201_MAGIC, SRC201_NONCE_SIZE,
    SRC201_TAG_SIZE, SRC201_VERSION,
};
use sumchain_primitives::{
    Address, Hash, MessagingOperation, SignedTransaction, SponsoredMessage, Transaction,
    TransactionV2, TxPayload,
};
use sumchain_state::mempool::InclusionPolicy;
use sumchain_state::{Mempool, MempoolConfig, StateManager};
use sumchain_storage::Database;
use tempfile::TempDir;

const CHAIN_ID: u64 = 1;

fn key(i: u8) -> KeyPair {
    KeyPair::from_bytes([i; 32])
}

/// One validator, V2 open, journals required from height 1, finality out of
/// reach.
fn genesis(validator: &KeyPair, funded: &[&KeyPair]) -> Genesis {
    let params = ChainParams {
        application_journal_enabled_from_height: Some(1),
        finality_depth: 1_000_000,
        ..ChainParams::with_v2_enabled()
    };
    let mut alloc = HashMap::new();
    for k in std::iter::once(validator).chain(funded.iter().copied()) {
        alloc.insert(k.address().to_base58(), 1_000_000_000u128);
    }
    Genesis::new(
        CHAIN_ID,
        0,
        vec![validator.public_key().to_base58()],
        alloc,
        params,
    )
}

fn transfer(from: &KeyPair, to: Address, amount: u128, nonce: u64) -> SignedTransaction {
    let tx = Transaction::new(CHAIN_ID, from.address(), to, amount, 10, nonce);
    let sig = sign(tx.signing_hash().as_bytes(), from.private_key());
    SignedTransaction::new(tx, *sig.as_bytes(), *from.public_key().as_bytes())
}

fn valid_message(rh: [u8; 32]) -> Vec<u8> {
    let header = MessageHeader {
        magic: SRC201_MAGIC,
        version: SRC201_VERSION,
        flags: MessageFlags::encrypted(),
        content_type: ContentType::TextPlain,
        attachment_count: 0,
        recipient_hash: rh,
        ephemeral_pubkey: [2u8; 32],
    };
    let mut v = header.to_bytes().to_vec();
    v.extend_from_slice(&[0u8; SRC201_NONCE_SIZE]);
    v.extend_from_slice(&[0u8, 0u8]);
    v.extend_from_slice(&[0u8; SRC201_TAG_SIZE]);
    v
}

/// A sponsored `SendMessage` from `relayer` whose envelope names `named` and
/// carries an all-zero signature.
fn zero_signature_envelope(
    relayer: &KeyPair,
    relayer_nonce: u64,
    named: &KeyPair,
    to: &Address,
) -> SignedTransaction {
    let rh = recipient_hash(to);
    let m = SponsoredMessage {
        message_data: valid_message(rh),
        recipient_hash: rh,
        signature: [0u8; 64],
        sender_pubkey: *named.public_key().as_bytes(),
        nonce: 0,
        expiry: u64::MAX,
        koppa_amount: None,
    };
    let tx = TransactionV2 {
        chain_id: CHAIN_ID,
        from: relayer.address(),
        fee: 1_000,
        nonce: relayer_nonce,
        payload: TxPayload::Messaging(MessagingTxData {
            operation: MessagingOperation::SendMessage,
            data: bincode::serialize(&m).unwrap(),
        }),
    };
    let sig = sign(tx.signing_hash().as_bytes(), relayer.private_key());
    SignedTransaction::new_v2(tx, *sig.as_bytes(), *relayer.public_key().as_bytes())
}

fn hashes(txs: &[SignedTransaction]) -> Vec<Hash> {
    txs.iter().map(|t| t.hash()).collect()
}

/// Block 1 is proposed from a one-transaction list. Block 2 is proposed from a
/// list that repeats that transaction, carries another one twice, and carries
/// an envelope whose signature does not verify: the produced block holds
/// exactly the two transactions the policy admits, in the order offered, and
/// the pool, which never held any of them, stays empty.
#[tokio::test]
async fn a_produced_block_carries_only_what_the_policy_admits_whatever_list_is_offered() {
    let validator = key(1);
    let alice = key(10);
    let bob = key(11);
    let carol = key(12);
    let g = genesis(&validator, &[&alice, &bob, &carol]);

    let dir = TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let state = Arc::new(StateManager::new(db.clone(), CHAIN_ID));
    let mempool = Arc::new(
        Mempool::new(MempoolConfig::default())
            .with_inclusion_policy(InclusionPolicy { db: db.clone() }),
    );
    let engine = PoAEngine::new(
        db.clone(),
        state,
        mempool.clone(),
        &g,
        Some(KeyPair::from_bytes(*validator.private_key().as_bytes())),
    )
    .unwrap();
    engine.init_genesis(&g).unwrap();

    let t = transfer(&alice, bob.address(), 5, 0);
    let b1 = engine.propose_block(vec![t.clone()]).await.unwrap();
    assert_eq!(hashes(&b1.transactions), vec![t.hash()]);

    let u = transfer(&bob, alice.address(), 3, 0);
    let w = transfer(&carol, alice.address(), 1, 0);
    // Alice's account nonce is 1 after `t`; her transaction carries the
    // envelope.
    let e = zero_signature_envelope(&alice, 1, &bob, &carol.address());
    let offered = vec![t.clone(), u.clone(), u.clone(), e.clone(), w.clone()];
    let b2 = engine.propose_block(offered).await.unwrap();
    assert_eq!(
        hashes(&b2.transactions),
        vec![u.hash(), w.hash()],
        "the included transaction, the repeated hash and the unverifiable envelope \
         are not carried"
    );
    assert!(
        mempool.is_empty(),
        "nothing offered from outside the pool is held"
    );
}
