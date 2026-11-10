//! The node-local inclusion policy (`Mempool::with_inclusion_policy`), at
//! admission and at selection.
//!
//! Every chain here is driven through the real block path (`execute_block` ->
//! `accept_produced` -> `publish`), under production's shape: V2 open,
//! sponsorship enabled by the registry admin, the block-timestamp gates closed.
//! The blocks are built BY HAND, so the chain advances however a test needs it
//! to — including by carrying a transaction the pool under test still holds,
//! which is what another proposer's block does to this node's pool.
//!
//! What the policy must do: admit and carry a sponsored envelope signed the
//! way the relay accepts today (either hex case of the recipient hash), refuse
//! one whose signature does not verify, require the sender's expected
//! messaging nonce, refuse what the canonical chain already includes, carry
//! each transaction and each (sender, nonce) once per block, re-check what it
//! holds when the chain moves, and not count a transaction stored only as a
//! side-branch row as included. Direct messages and every other transaction
//! are unaffected, and a pool without the policy behaves as before.

mod common;

use std::sync::Arc;

use common::{fund, setup_with_params, CHAIN_ID};
use sumchain_crypto::{recipient_hash, sign, KeyPair};
use sumchain_genesis::{ChainParams, MessagingParams};
use sumchain_primitives::messaging::{
    ContentType, FundRegistryData, MessageFlags, MessageHeader, MessagingTxData,
    RegisterPublicKeyData, SendMessageData, SetSponsorshipEnabledData, SRC201_MAGIC,
    SRC201_NONCE_SIZE, SRC201_TAG_SIZE, SRC201_VERSION,
};
use sumchain_primitives::{
    Address, Block, BlockHeader, Hash, MessagingOperation, Receipt, SignedTransaction,
    SponsoredMessage, TransactionV2, TxPayload, TxStatus,
};
use sumchain_state::executor::BlockExecutor;
use sumchain_state::mempool::{InclusionPolicy, Mempool, MempoolConfig};
use sumchain_state::state::StateManager;
use sumchain_state::StateError;
use sumchain_storage::{Database, MessagingStore, ReceiptStore, TxStore};

const T_MS: u64 = 1_760_000_000_000;
const MINUTE_MS: u64 = 60_000;
const FEE: u128 = 100;
const FUNDS: u128 = 1_000_000_000;
const NEVER: u64 = u64::MAX;
const PROPOSER_PK: [u8; 32] = [0x77; 32];

fn admin() -> KeyPair {
    KeyPair::from_bytes([0x31; 32])
}
/// A registered user who signs its own envelopes.
fn sender() -> KeyPair {
    KeyPair::from_bytes([0x32; 32])
}
/// Any funded account that relays envelopes.
fn relayer() -> KeyPair {
    KeyPair::from_bytes([0x33; 32])
}
fn recipient() -> KeyPair {
    KeyPair::from_bytes([0x34; 32])
}
/// A second relayer.
fn other_relayer() -> KeyPair {
    KeyPair::from_bytes([0x35; 32])
}
/// A registered user who is not `sender()`.
fn someone_else() -> KeyPair {
    KeyPair::from_bytes([0x36; 32])
}

fn base() -> ChainParams {
    let mut p = ChainParams::with_v2_enabled();
    p.messaging = Some(MessagingParams {
        registry_admin: Some(admin().address().to_base58()),
        ..MessagingParams::default()
    });
    p
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

fn op(operation: MessagingOperation, payload: &impl serde::Serialize) -> MessagingTxData {
    MessagingTxData {
        operation,
        data: bincode::serialize(payload).unwrap(),
    }
}

fn signed_payload(kp: &KeyPair, nonce: u64, fee: u128, payload: TxPayload) -> SignedTransaction {
    let tx = TransactionV2 {
        chain_id: CHAIN_ID,
        from: kp.address(),
        fee,
        nonce,
        payload,
    };
    let sig = sign(tx.signing_hash().as_bytes(), kp.private_key());
    SignedTransaction::new_v2(tx, *sig.as_bytes(), *kp.public_key().as_bytes())
}

fn messaging_tx(kp: &KeyPair, nonce: u64, data: MessagingTxData) -> SignedTransaction {
    signed_payload(kp, nonce, FEE, TxPayload::Messaging(data))
}

fn messaging_tx_with_fee(
    kp: &KeyPair,
    nonce: u64,
    fee: u128,
    data: MessagingTxData,
) -> SignedTransaction {
    signed_payload(kp, nonce, fee, TxPayload::Messaging(data))
}

fn transfer(from: &KeyPair, nonce: u64, to: &Address) -> SignedTransaction {
    signed_payload(from, nonce, FEE, TxPayload::Transfer { to: *to, amount: 1 })
}

fn fund_registry(kp: &KeyPair, nonce: u64) -> SignedTransaction {
    messaging_tx(
        kp,
        nonce,
        op(
            MessagingOperation::FundRegistry,
            &FundRegistryData { amount: 1_000 },
        ),
    )
}

fn direct(from: &KeyPair, nonce: u64, to: &Address) -> SignedTransaction {
    let rh = recipient_hash(to);
    messaging_tx(
        from,
        nonce,
        op(
            MessagingOperation::SendMessageDirect,
            &SendMessageData {
                message_data: valid_message(rh),
                recipient_hash: rh,
            },
        ),
    )
}

/// An envelope naming `sender_pubkey`, with an all-zero signature.
fn envelope(sender_pubkey: [u8; 32], to: &Address, nonce: u64) -> SponsoredMessage {
    let rh = recipient_hash(to);
    SponsoredMessage {
        message_data: valid_message(rh),
        recipient_hash: rh,
        signature: [0u8; 64],
        sender_pubkey,
        nonce,
        expiry: NEVER,
        koppa_amount: None,
    }
}

/// The string `messaging_submitSponsored` verifies, with the recipient hash
/// rendered as `recipient_hex` — the client's own rendering, minus `0x`.
fn relay_preimage(m: &SponsoredMessage, recipient_hex: &str) -> Vec<u8> {
    format!(
        "SUMCHAIN_SPONSORED_MSG:{}:{}:{}:{}",
        m.nonce,
        m.expiry,
        recipient_hex,
        hex::encode(blake3::hash(&m.message_data).as_bytes())
    )
    .into_bytes()
}

/// `m` signed by `signer` over the relay preimage, lower-case recipient hex.
fn relay_signed(mut m: SponsoredMessage, signer: &KeyPair) -> SponsoredMessage {
    let hex = hex::encode(m.recipient_hash);
    m.signature = *sign(&relay_preimage(&m, &hex), signer.private_key()).as_bytes();
    m
}

/// `m` signed by `signer` over the relay preimage, upper-case recipient hex.
fn relay_signed_upper(mut m: SponsoredMessage, signer: &KeyPair) -> SponsoredMessage {
    let hex = hex::encode(m.recipient_hash).to_uppercase();
    m.signature = *sign(&relay_preimage(&m, &hex), signer.private_key()).as_bytes();
    m
}

/// `sender()`'s own envelope to `recipient()` at `nonce`, relay-signed.
fn own_envelope(nonce: u64) -> SponsoredMessage {
    relay_signed(
        envelope(
            *sender().public_key().as_bytes(),
            &recipient().address(),
            nonce,
        ),
        &sender(),
    )
}

fn sponsored_tx(relayer: &KeyPair, relayer_nonce: u64, m: &SponsoredMessage) -> SignedTransaction {
    messaging_tx(
        relayer,
        relayer_nonce,
        op(MessagingOperation::SendMessage, m),
    )
}

fn sponsored_tx_with_fee(
    relayer: &KeyPair,
    relayer_nonce: u64,
    fee: u128,
    m: &SponsoredMessage,
) -> SignedTransaction {
    messaging_tx_with_fee(
        relayer,
        relayer_nonce,
        fee,
        op(MessagingOperation::SendMessage, m),
    )
}

fn hashes(txs: &[SignedTransaction]) -> Vec<Hash> {
    txs.iter().map(|t| t.hash()).collect()
}

fn refused(r: &Result<Hash, StateError>) -> bool {
    matches!(r, Err(StateError::SponsoredEnvelopeRefused(_)))
}

fn included(r: &Result<Hash, StateError>) -> bool {
    matches!(r, Err(StateError::TransactionAlreadyIncluded))
}

/// A chain under test, executed block by block, with pools over its database.
struct Chain {
    state: Arc<StateManager>,
    db: Arc<Database>,
    _dir: tempfile::TempDir,
    exec: BlockExecutor,
    height: u64,
}

impl Chain {
    /// A chain with sponsorship enabled and `sender()`, `recipient()` and
    /// `someone_else()` registered (block 1).
    fn ready() -> Self {
        let (state, db, dir, exec) = setup_with_params(base());
        for kp in [
            admin(),
            sender(),
            relayer(),
            recipient(),
            other_relayer(),
            someone_else(),
        ] {
            fund(&db, &kp, FUNDS);
        }
        let mut c = Self {
            state,
            db,
            _dir: dir,
            exec,
            height: 0,
        };
        let mut txs = vec![messaging_tx(
            &admin(),
            0,
            op(
                MessagingOperation::SetSponsorshipEnabled,
                &SetSponsorshipEnabledData { enabled: true },
            ),
        )];
        for kp in [sender(), recipient(), someone_else()] {
            txs.push(messaging_tx(
                &kp,
                0,
                op(
                    MessagingOperation::RegisterPublicKey,
                    &RegisterPublicKeyData {
                        public_key: *kp.public_key().as_bytes(),
                    },
                ),
            ));
        }
        let receipts = c.block(txs);
        assert!(receipts.iter().all(|r| r.status == TxStatus::Success));
        c
    }

    /// A pool with this node's inclusion policy over this chain's database.
    fn pool(&self) -> Mempool {
        Mempool::new(MempoolConfig::default()).with_inclusion_policy(InclusionPolicy {
            db: self.db.clone(),
        })
    }

    /// Execute and publish the next block, as a proposer applying no policy
    /// would, and WITHOUT telling any pool.
    fn block(&mut self, txs: Vec<SignedTransaction>) -> Vec<Receipt> {
        let height = self.height + 1;
        let ts = T_MS + height * MINUTE_MS;
        let header = BlockHeader::new(Hash::ZERO, height, ts, Hash::ZERO, Hash::ZERO, PROPOSER_PK);
        let mut block = Block::new(header, txs);
        let exec = self
            .exec
            .execute_block(&block, self.state.state_root(), &[])
            .expect("the block executes");
        block.header.state_root = exec.computed_root();
        let (executed, _state_diff, _contract_diff) = exec.into_parts();
        let receipts = executed.receipts().to_vec();
        let accepted = executed.accept_produced(&block).expect("accept_produced");
        let accumulator = accepted.accumulator();
        accepted.publish().expect("publish");
        self.state.set_state_root(accumulator);
        self.height = height;
        receipts
    }

    fn one(&mut self, tx: SignedTransaction) -> Receipt {
        let mut r = self.block(vec![tx]);
        assert_eq!(r.len(), 1);
        r.remove(0)
    }

    fn messaging_nonce(&self, a: &Address) -> u64 {
        MessagingStore::new(&self.db).get_sender_nonce(a).unwrap()
    }

    fn has_receipt(&self, h: &Hash) -> bool {
        ReceiptStore::new(&self.db).contains(h).unwrap()
    }
}

// ── authentication ───────────────────────────────────────────────────────────

/// An envelope signed the way the relay checks it is admitted, selected,
/// carried and executed; once the chain carries it, the pool evicts it.
#[test]
fn a_relay_signed_envelope_is_admitted_selected_and_executes() {
    let mut c = Chain::ready();
    let pool = c.pool();
    let tx = sponsored_tx(&relayer(), 0, &own_envelope(0));

    pool.add(tx.clone()).expect("admitted");
    let selected = pool.select_for_block(10);
    assert_eq!(hashes(&selected), vec![tx.hash()]);
    assert_eq!(pool.apply_inclusion_policy(vec![tx.clone()]).len(), 1);

    let r = c.one(tx.clone());
    assert_eq!(r.status, TxStatus::Success);
    assert_eq!(c.messaging_nonce(&sender().address()), 1);

    // The pool was not told. It finds out at selection and evicts.
    assert!(pool.contains(&tx.hash()));
    assert!(pool.select_for_block(10).is_empty());
    assert!(!pool.contains(&tx.hash()));
    assert!(included(&pool.add(tx)));
}

/// The relay embeds the recipient hash as the client typed it, so a client
/// that signs over upper-case hex reaches the relay today and reaches this
/// policy too. A mixed-case rendering is not tried: it is refused here, and no
/// known client produces one.
#[test]
fn either_hex_case_of_the_recipient_hash_is_accepted() {
    let c = Chain::ready();
    let pool = c.pool();
    let upper = relay_signed_upper(
        envelope(*sender().public_key().as_bytes(), &recipient().address(), 0),
        &sender(),
    );
    pool.add(sponsored_tx(&relayer(), 0, &upper))
        .expect("upper-case admitted");

    let pool = c.pool();
    let mut mixed = envelope(*sender().public_key().as_bytes(), &recipient().address(), 0);
    let hex = hex::encode(mixed.recipient_hash);
    let (head, tail) = hex.split_at(32);
    let mixed_hex = format!("{}{}", head.to_uppercase(), tail);
    mixed.signature = *sign(&relay_preimage(&mixed, &mixed_hex), sender().private_key()).as_bytes();
    assert!(refused(&pool.add(sponsored_tx(&relayer(), 0, &mixed))));
}

/// An envelope whose signature does not verify by the key it names — all
/// zeros, another key's signature, or bytes that do not decode — is refused at
/// admission and dropped at selection. The pool never holds one.
#[test]
fn an_envelope_whose_signature_does_not_verify_is_refused_at_admission_and_at_selection() {
    let c = Chain::ready();
    let pool = c.pool();
    let zero = sponsored_tx(
        &relayer(),
        0,
        &envelope(*sender().public_key().as_bytes(), &recipient().address(), 0),
    );
    let by_another = sponsored_tx(
        &other_relayer(),
        0,
        &relay_signed(
            envelope(*sender().public_key().as_bytes(), &recipient().address(), 0),
            &someone_else(),
        ),
    );
    let undecodable = messaging_tx(
        &relayer(),
        0,
        MessagingTxData {
            operation: MessagingOperation::SendMessage,
            data: vec![0xff; 7],
        },
    );
    for tx in [&zero, &by_another, &undecodable] {
        assert!(refused(&pool.add(tx.clone())), "{tx:?}");
    }
    assert!(pool.is_empty());

    // At selection: a list a caller offers directly.
    let good = sponsored_tx(&relayer(), 0, &own_envelope(0));
    let carried = pool.apply_inclusion_policy(vec![
        zero.clone(),
        good.clone(),
        by_another.clone(),
        undecodable.clone(),
    ]);
    assert_eq!(hashes(&carried), vec![good.hash()]);
}

// ── the expected messaging nonce ─────────────────────────────────────────────

/// The envelope nonce continues the sender's sequence: the committed messaging
/// nonce, then one per envelope already pending. Below is used, a pending
/// value is a duplicate, beyond the run is ahead. A run admitted in any fee
/// order is carried in nonce order, in one block.
#[test]
fn the_envelope_nonce_must_continue_the_senders_sequence() {
    let mut c = Chain::ready();
    let pool = c.pool();
    assert_eq!(c.messaging_nonce(&sender().address()), 0);

    assert!(refused(&pool.add(sponsored_tx(
        &relayer(),
        0,
        &own_envelope(1)
    ))));
    let e0 = sponsored_tx_with_fee(&relayer(), 0, FEE, &own_envelope(0));
    pool.add(e0.clone()).expect("nonce 0 admitted");
    // The same (sender, nonce) relayed by someone else: a duplicate.
    assert!(refused(&pool.add(sponsored_tx(
        &other_relayer(),
        0,
        &own_envelope(0)
    ))));
    let e1 = sponsored_tx_with_fee(&relayer(), 0, FEE * 2, &own_envelope(1));
    let e2 = sponsored_tx_with_fee(&relayer(), 0, FEE * 3, &own_envelope(2));
    pool.add(e1.clone()).expect("nonce 1 admitted behind 0");
    pool.add(e2.clone()).expect("nonce 2 admitted behind 1");
    assert!(refused(&pool.add(sponsored_tx(
        &relayer(),
        0,
        &own_envelope(4)
    ))));

    // Fee order offers 2, 1, 0. The block carries 0, 1, 2.
    let selected = pool.select_for_block(10);
    assert_eq!(hashes(&selected), vec![e0.hash(), e1.hash(), e2.hash()]);
    // With room for only two, the sequence still starts at 0.
    assert_eq!(
        hashes(&pool.select_for_block(2)),
        vec![e0.hash(), e1.hash()]
    );

    // Executed as carried: the sender's nonce reaches 3. The held copies are
    // then evicted, and the next envelope must carry 3.
    let receipts = c.block(selected);
    assert!(receipts.iter().all(|r| r.status == TxStatus::Success));
    assert_eq!(c.messaging_nonce(&sender().address()), 3);
    assert!(pool.select_for_block(10).is_empty());
    assert!(pool.is_empty());
    assert!(refused(&pool.add(sponsored_tx(
        &relayer(),
        0,
        &own_envelope(2)
    ))));
    pool.add(sponsored_tx(&relayer(), 0, &own_envelope(3)))
        .expect("nonce 3 admitted");
}

/// A gap left by an evicted envelope can be filled: with nonce 1 pending and
/// nonce 0 gone, nonce 0 is admitted again and the pair is carried in order.
#[test]
fn a_gap_left_by_an_evicted_envelope_can_be_filled() {
    let c = Chain::ready();
    let pool = c.pool();
    let e0 = sponsored_tx(&relayer(), 0, &own_envelope(0));
    let e1 = sponsored_tx(&other_relayer(), 0, &own_envelope(1));
    pool.add(e0.clone()).unwrap();
    pool.add(e1.clone()).unwrap();
    pool.remove(&e0.hash());
    // Alone, nonce 1 is ahead of the sequence: not carried, not evicted.
    assert!(pool.select_for_block(10).is_empty());
    assert!(pool.contains(&e1.hash()));
    assert!(refused(&pool.add(sponsored_tx(
        &relayer(),
        0,
        &own_envelope(2)
    ))));
    pool.add(e0.clone()).expect("the gap is filled");
    assert_eq!(
        hashes(&pool.select_for_block(10)),
        vec![e0.hash(), e1.hash()]
    );
}

// ── canonical inclusion ──────────────────────────────────────────────────────

/// A transaction the canonical chain already carries — here a messaging
/// operation that leaves its signer's account nonce unchanged, and a transfer —
/// is refused at admission; one admitted BEFORE the chain carried it is evicted
/// at selection and by revalidation.
#[test]
fn a_transaction_already_on_the_canonical_chain_is_refused_and_evicted() {
    let mut c = Chain::ready();
    let f = fund_registry(&someone_else(), 0);
    let t = transfer(&relayer(), 0, &recipient().address());

    // Held first, carried by someone else's block second.
    let held = c.pool();
    held.add(f.clone()).unwrap();
    held.add(t.clone()).unwrap();
    let receipts = c.block(vec![f.clone(), t.clone()]);
    assert!(receipts.iter().all(|r| r.status == TxStatus::Success));
    assert!(c.has_receipt(&f.hash()) && c.has_receipt(&t.hash()));

    // A fresh pool (a restarted node) refuses both outright.
    let fresh = c.pool();
    assert!(included(&fresh.add(f.clone())));
    assert!(included(&fresh.add(t.clone())));

    // The pool that held them finds out at selection ...
    assert!(held.select_for_block(10).is_empty());
    assert!(held.is_empty());

    // ... or at revalidation.
    let held = c.pool();
    // The relayer's transfer above moved its account nonce to 1.
    let g = fund_registry(&relayer(), 1);
    held.add(g.clone()).unwrap();
    c.block(vec![g.clone()]);
    assert!(held.contains(&g.hash()));
    held.revalidate(&c.state, CHAIN_ID);
    assert!(!held.contains(&g.hash()));
}

/// A transaction stored in `TRANSACTIONS` without a receipt — the rows a block
/// archived off the canonical chain leaves behind — is not counted as included.
#[test]
fn a_transaction_stored_only_as_a_side_branch_row_is_not_counted_as_included() {
    let c = Chain::ready();
    let t = transfer(&relayer(), 0, &recipient().address());
    TxStore::new(&c.db).put(&t).unwrap();
    assert!(TxStore::new(&c.db).contains(&t.hash()).unwrap());
    assert!(!c.has_receipt(&t.hash()));
    let pool = c.pool();
    pool.add(t.clone()).expect("admitted: no canonical receipt");
    assert_eq!(hashes(&pool.select_for_block(10)), vec![t.hash()]);
}

// ── within one block ─────────────────────────────────────────────────────────

/// A candidate block carries each transaction hash once and each (sender,
/// nonce) envelope once, keeping the first occurrence of each.
#[test]
fn a_candidate_block_carries_each_transaction_and_each_envelope_once() {
    let c = Chain::ready();
    let pool = c.pool();
    let f = fund_registry(&someone_else(), 0);
    let e0 = sponsored_tx(&relayer(), 0, &own_envelope(0));
    // The same envelope, relayed by another account: a different transaction
    // hash, the same (sender, nonce).
    let e0_again = sponsored_tx(&other_relayer(), 0, &own_envelope(0));
    let t = transfer(&relayer(), 0, &recipient().address());
    let carried = pool.apply_inclusion_policy(vec![
        f.clone(),
        f.clone(),
        e0.clone(),
        e0_again.clone(),
        t.clone(),
        t.clone(),
    ]);
    assert_eq!(hashes(&carried), vec![f.hash(), e0.hash(), t.hash()]);
    // Nothing offered from outside the pool was evicted from it: the pool
    // never held them.
    assert!(pool.is_empty());
}

// ── recheck when the chain moves ─────────────────────────────────────────────

/// A held envelope is judged against the chain as it stands at selection: when
/// another block has moved the sender's nonce past it, it is evicted, and the
/// next envelope must carry the new value. A fresh pool over the same database
/// refuses the stale envelope outright.
#[test]
fn held_envelopes_are_rechecked_against_the_chain_before_selection() {
    let mut c = Chain::ready();
    let pool = c.pool();
    let e0 = sponsored_tx(&relayer(), 0, &own_envelope(0));
    pool.add(e0.clone()).unwrap();

    // The sender's own direct message, carried by someone else's block, moves
    // the nonce to 1.
    let r = c.one(direct(&sender(), 0, &recipient().address()));
    assert_eq!(r.status, TxStatus::Success);
    assert_eq!(c.messaging_nonce(&sender().address()), 1);

    assert!(pool.contains(&e0.hash()));
    assert!(pool.select_for_block(10).is_empty());
    assert!(!pool.contains(&e0.hash()));
    assert!(refused(&pool.add(e0.clone())));
    let e1 = sponsored_tx(&relayer(), 0, &own_envelope(1));
    pool.add(e1.clone()).expect("nonce 1 is now expected");
    assert_eq!(hashes(&pool.select_for_block(10)), vec![e1.hash()]);

    // Revalidation does the same.
    let pool = c.pool();
    let e1b = sponsored_tx(&other_relayer(), 0, &own_envelope(1));
    pool.add(e1b.clone()).unwrap();
    c.one(e1.clone());
    assert_eq!(c.messaging_nonce(&sender().address()), 2);
    pool.revalidate(&c.state, CHAIN_ID);
    assert!(!pool.contains(&e1b.hash()));

    // A restarted node starts with an empty pool; re-submission is refused.
    let restarted = c.pool();
    assert!(refused(&restarted.add(e1b)));
    assert!(included(&restarted.add(e1)));
}

// ── what is unaffected ───────────────────────────────────────────────────────

/// Direct messages, messages with payment paths, transfers and the other
/// messaging operations are admitted and carried exactly as before.
#[test]
fn direct_messages_and_other_transactions_are_unaffected() {
    let mut c = Chain::ready();
    let pool = c.pool();
    let d = direct(&sender(), 0, &recipient().address());
    let t = transfer(&relayer(), 0, &recipient().address());
    let f = fund_registry(&someone_else(), 0);
    for tx in [&d, &t, &f] {
        pool.add(tx.clone()).expect("admitted");
    }
    let selected = pool.select_for_block(10);
    assert_eq!(selected.len(), 3);
    let receipts = c.block(selected);
    assert!(receipts.iter().all(|r| r.status == TxStatus::Success));
    assert_eq!(c.messaging_nonce(&sender().address()), 1);
}

/// Without a wired policy the pool behaves as it always has: an envelope with
/// an all-zero signature and a transaction the chain already carries are both
/// admitted. The policy is the production wiring, not the default.
#[test]
fn without_a_wired_policy_the_pool_behaves_as_before() {
    let mut c = Chain::ready();
    let t = transfer(&relayer(), 0, &recipient().address());
    c.one(t.clone());
    let bare = Mempool::new(MempoolConfig::default());
    assert!(!bare.has_inclusion_policy());
    bare.add(t).expect("admitted without a policy");
    bare.add(sponsored_tx(
        &relayer(),
        0,
        &envelope(*sender().public_key().as_bytes(), &recipient().address(), 0),
    ))
    .expect("admitted without a policy");
    assert_eq!(bare.select_for_block(10).len(), 2);
    assert!(c.pool().has_inclusion_policy());
}

/// The relay string this file signs over is byte-identical to what the policy
/// verifies: a message carrying an amount, a late expiry and a non-trivial
/// nonce is accepted when signed over it and refused when any covered field is
/// changed afterwards.
#[test]
fn the_signature_covers_nonce_expiry_recipient_and_message_bytes() {
    let mut c = Chain::ready();
    // Move the sender's nonce to 1 so a non-zero envelope nonce is expected.
    c.one(direct(&sender(), 0, &recipient().address()));
    let pool = c.pool();
    let mut m = envelope(*sender().public_key().as_bytes(), &recipient().address(), 1);
    m.expiry = 1_900_000_000;
    m.koppa_amount = Some(5);
    let m = relay_signed(m, &sender());
    pool.add(sponsored_tx(&relayer(), 0, &m)).expect("admitted");

    for (what, tamper) in [
        (
            "nonce",
            Box::new(|x: &mut SponsoredMessage| x.nonce = 2) as Box<dyn Fn(&mut SponsoredMessage)>,
        ),
        ("expiry", Box::new(|x: &mut SponsoredMessage| x.expiry += 1)),
        (
            "recipient",
            Box::new(|x: &mut SponsoredMessage| x.recipient_hash[0] ^= 1),
        ),
        (
            "message",
            Box::new(|x: &mut SponsoredMessage| {
                let n = x.message_data.len();
                x.message_data[n - 1] ^= 1;
            }),
        ),
    ] {
        let mut changed = m.clone();
        tamper(&mut changed);
        let pool = c.pool();
        assert!(
            refused(&pool.add(sponsored_tx(&other_relayer(), 0, &changed))),
            "{what}"
        );
    }
    // The amount is NOT covered by the relay preimage: a relayer may change
    // it and the envelope still verifies. Documented, not fixed here.
    let mut amended = m.clone();
    amended.koppa_amount = Some(6);
    c.pool()
        .add(sponsored_tx(&other_relayer(), 0, &amended))
        .expect("the amount is outside the signed string");
}
