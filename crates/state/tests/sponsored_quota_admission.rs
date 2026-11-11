//! The inclusion policy's rule 4: a sponsored envelope's sender has quota left
//! for it (`Mempool::with_messaging_quota_admission`).
//!
//! The envelope that takes a sender past its quota cannot be executed: the
//! executor's `check_rate_limit` refuses it with an ERROR, not a receipt, so
//! no block can carry it while the count stands. With rule 4 the pool refuses
//! it at admission and the relay returns the reason to its caller.
//!
//! Every chain here is driven through the real block path (`execute_block` ->
//! `accept_produced` -> `publish`), sponsorship enabled by the registry admin.
//! What is pinned: the refusal at and over the quota, and only there; pending
//! envelopes counted; the staked multiplier honoured; the bucket read where the
//! executor reads it, with the clock gates closed and open; the refusal exact
//! (what is refused cannot execute, what is admitted can); and nothing changes
//! without the admission wired.

mod common;

use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use common::{fund, setup_with_params, CHAIN_ID};
use sumchain_crypto::{recipient_hash, sign, KeyPair};
use sumchain_genesis::{ChainParams, MessagingParams};
use sumchain_primitives::messaging::{
    ContentType, MessageFlags, MessageHeader, MessagingTxData, RegisterPublicKeyData,
    SetDailyQuotaData, SetSponsorshipEnabledData, StakeForTrustData, SRC201_MAGIC,
    SRC201_NONCE_SIZE, SRC201_TAG_SIZE, SRC201_VERSION,
};
use sumchain_primitives::{
    Block, BlockHeader, Hash, MessagingOperation, Receipt, SignedTransaction, SponsoredMessage,
    TransactionV2, TxPayload, TxStatus, DEFAULT_MIN_TRUST_STAKE,
};
use sumchain_state::executor::BlockExecutor;
use sumchain_state::mempool::{InclusionPolicy, Mempool, MempoolConfig, MessagingQuotaAdmission};
use sumchain_state::messaging_executor::{
    MessagingExecutor, MESSAGING_DAY_SECONDS, STAKED_SENDER_QUOTA_MULTIPLIER,
};
use sumchain_state::state::StateManager;
use sumchain_state::StateError;
use sumchain_storage::{Database, MessagingStore};

const FEE: u128 = 100;
const RELAY_FEE: u128 = 1_000_000;
const FUNDS: u128 = 1_000_000_000_000;
const EXPIRY: u64 = 4_000_000_000;
const PROPOSER_PK: [u8; 32] = [0x77; 32];
/// A past day, far from today's wall clock.
const PAST_MS: u64 = 1_760_000_000_000;
const MINUTE_MS: u64 = 60_000;
const QUOTA: u32 = 2;

fn admin() -> KeyPair {
    KeyPair::from_bytes([0x41; 32])
}
fn relay() -> KeyPair {
    KeyPair::from_bytes([0x42; 32])
}
fn sender() -> KeyPair {
    KeyPair::from_bytes([0x43; 32])
}
fn recipient() -> KeyPair {
    KeyPair::from_bytes([0x44; 32])
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// Production's shape: the clock gates closed.
fn closed() -> ChainParams {
    let mut p = ChainParams::with_v2_enabled();
    p.messaging = Some(MessagingParams {
        registry_admin: Some(admin().address().to_base58()),
        ..MessagingParams::default()
    });
    p
}

/// Both messaging clock gates open from genesis: the quota bucket is the
/// block's day.
fn open() -> ChainParams {
    let mut p = closed();
    p.subsystem_block_timestamp_enabled_from_height = Some(0);
    p.messaging_timestamp_units_enabled_from_height = Some(0);
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

fn signed(kp: &KeyPair, nonce: u64, fee: u128, data: MessagingTxData) -> SignedTransaction {
    let tx = TransactionV2 {
        chain_id: CHAIN_ID,
        from: kp.address(),
        fee,
        nonce,
        payload: TxPayload::Messaging(data),
    };
    let sig = sign(tx.signing_hash().as_bytes(), kp.private_key());
    SignedTransaction::new_v2(tx, *sig.as_bytes(), *kp.public_key().as_bytes())
}

/// `sender()`'s envelope at messaging nonce `nonce`, relay-signed, wrapped as
/// `messaging_submitSponsored` wraps it.
fn envelope(nonce: u64) -> SignedTransaction {
    let user = sender();
    let rh = recipient_hash(&recipient().address());
    let message_data = valid_message(rh);
    let preimage = format!(
        "SUMCHAIN_SPONSORED_MSG:{}:{}:{}:{}",
        nonce,
        EXPIRY,
        hex::encode(rh),
        hex::encode(blake3::hash(&message_data).as_bytes())
    );
    let m = SponsoredMessage {
        message_data,
        recipient_hash: rh,
        signature: *sign(preimage.as_bytes(), user.private_key()).as_bytes(),
        sender_pubkey: *user.public_key().as_bytes(),
        nonce,
        expiry: EXPIRY,
        koppa_amount: None,
    };
    signed(
        &relay(),
        0,
        RELAY_FEE,
        op(MessagingOperation::SendMessage, &m),
    )
}

fn refused_for_quota(r: &Result<Hash, StateError>) -> bool {
    matches!(r, Err(StateError::SponsoredEnvelopeRefused(why)) if why.contains("quota"))
}

/// A chain under test, executed block by block.
struct Chain {
    params: ChainParams,
    state: Arc<StateManager>,
    db: Arc<Database>,
    _dir: tempfile::TempDir,
    exec: BlockExecutor,
    height: u64,
    /// The first block's timestamp; each later block is a minute later.
    t0: u64,
}

impl Chain {
    /// Sponsorship on, the quota at `QUOTA`, `sender()` registered.
    fn ready(params: ChainParams, t0: u64) -> Self {
        let (state, db, dir, exec) = setup_with_params(params.clone());
        for kp in [admin(), relay(), sender(), recipient()] {
            fund(&db, &kp, FUNDS);
        }
        let mut c = Self {
            params,
            state,
            db,
            _dir: dir,
            exec,
            height: 0,
            t0,
        };
        // A messaging admin operation advances no account nonce.
        let setup = [
            signed(
                &admin(),
                0,
                FEE,
                op(
                    MessagingOperation::SetSponsorshipEnabled,
                    &SetSponsorshipEnabledData { enabled: true },
                ),
            ),
            signed(
                &admin(),
                0,
                FEE,
                op(
                    MessagingOperation::SetDailyQuota,
                    &SetDailyQuotaData { quota: QUOTA },
                ),
            ),
            signed(
                &sender(),
                0,
                FEE,
                op(
                    MessagingOperation::RegisterPublicKey,
                    &RegisterPublicKeyData {
                        public_key: *sender().public_key().as_bytes(),
                    },
                ),
            ),
        ];
        for tx in setup {
            assert_eq!(c.one(tx).status, TxStatus::Success, "setup");
        }
        c
    }

    fn block_ts(&self, height: u64) -> u64 {
        self.t0 + (height - 1) * MINUTE_MS
    }

    fn try_block(&mut self, txs: Vec<SignedTransaction>) -> Result<Vec<Receipt>, StateError> {
        let height = self.height + 1;
        let header = BlockHeader::new(
            Hash::ZERO,
            height,
            self.block_ts(height),
            Hash::ZERO,
            Hash::ZERO,
            PROPOSER_PK,
        );
        let mut block = Block::new(header, txs);
        let exec = self
            .exec
            .execute_block(&block, self.state.state_root(), &[])?;
        block.header.state_root = exec.computed_root();
        let (executed, _state_diff, _contract_diff) = exec.into_parts();
        let receipts = executed.receipts().to_vec();
        let accepted = executed.accept_produced(&block).expect("accept_produced");
        let accumulator = accepted.accumulator();
        accepted.publish().expect("publish");
        self.state.set_state_root(accumulator);
        self.height = height;
        Ok(receipts)
    }

    fn one(&mut self, tx: SignedTransaction) -> Receipt {
        let mut r = self.try_block(vec![tx]).expect("the block executes");
        assert_eq!(r.len(), 1);
        r.remove(0)
    }

    /// `sender()` sends `n` envelopes, starting at its current nonce.
    fn send(&mut self, n: u64) {
        for _ in 0..n {
            let next = self.messaging_nonce();
            assert_eq!(self.one(envelope(next)).status, TxStatus::Success);
        }
    }

    fn messaging_nonce(&self) -> u64 {
        MessagingStore::new(&self.db)
            .get_sender_nonce(&sender().address())
            .unwrap()
    }

    /// A pool with the inclusion policy, with or without rule 4, as the node
    /// wires it: the chain's parameters and its live height.
    fn pool(&self, with_quota: bool) -> Mempool {
        let pool = Mempool::new(MempoolConfig::default()).with_inclusion_policy(InclusionPolicy {
            db: self.db.clone(),
        });
        if !with_quota {
            return pool;
        }
        pool.with_messaging_quota_admission(MessagingQuotaAdmission {
            params: Arc::new(self.params.clone()),
            current_height: Arc::new(AtomicU64::new(self.height)),
        })
    }
}

// ── refused at the quota, and only there ────────────────────────────────────

/// Under the quota the envelope is admitted; at it the next one is refused,
/// with the count in the reason. A pool without rule 4 admits it as before.
#[test]
fn an_envelope_beyond_the_senders_quota_is_refused_with_the_count() {
    let mut c = Chain::ready(closed(), PAST_MS);
    c.send(1);
    c.pool(true)
        .add(envelope(1))
        .expect("the second of two is admitted");

    c.send(1);
    let r = c.pool(true).add(envelope(2));
    assert!(refused_for_quota(&r), "{r:?}");
    let Err(StateError::SponsoredEnvelopeRefused(why)) = r else {
        unreachable!()
    };
    assert!(why.contains("used 2 of its 2"), "{why}");

    c.pool(false)
        .add(envelope(2))
        .expect("without rule 4 the pool admits it, as before");
}

/// Envelopes already pending for the sender count: each is carried before
/// this one and uses a message when it succeeds.
#[test]
fn pending_envelopes_count_against_the_quota() {
    let mut c = Chain::ready(closed(), PAST_MS);
    c.send(1);
    let pool = c.pool(true);
    pool.add(envelope(1)).expect("1 used + 0 pending < 2");
    let r = pool.add(envelope(2));
    assert!(refused_for_quota(&r), "{r:?}");
    let Err(StateError::SponsoredEnvelopeRefused(why)) = r else {
        unreachable!()
    };
    assert!(why.contains("1 more"), "{why}");
}

/// A sender whose trust stake meets the minimum has the multiplied quota, as
/// `check_rate_limit` reads it.
#[test]
fn a_staked_sender_has_the_multiplied_quota() {
    let mut c = Chain::ready(closed(), PAST_MS);
    c.send(QUOTA as u64);
    assert!(refused_for_quota(&c.pool(true).add(envelope(QUOTA as u64))));

    let stake = signed(
        &sender(),
        0,
        FEE,
        op(
            MessagingOperation::StakeForTrust,
            &StakeForTrustData {
                amount: DEFAULT_MIN_TRUST_STAKE,
            },
        ),
    );
    assert_eq!(c.one(stake).status, TxStatus::Success);
    c.pool(true)
        .add(envelope(QUOTA as u64))
        .expect("the staked quota has room");
    let staked = (QUOTA * STAKED_SENDER_QUOTA_MULTIPLIER) as u64;
    c.send(staked - QUOTA as u64);
    assert!(refused_for_quota(&c.pool(true).add(envelope(staked))));
}

// ── the bucket ──────────────────────────────────────────────────────────────

/// With the clock gates closed every block counts in one bucket, whatever its
/// timestamp: messages sent long ago still count today.
#[test]
fn with_the_clock_gates_closed_every_message_counts_in_one_bucket() {
    assert_eq!(MessagingExecutor::quota_day(&closed(), 5, PAST_MS), 0);
    assert_eq!(MessagingExecutor::quota_day(&closed(), 5, now_ms()), 0);
    let mut c = Chain::ready(closed(), PAST_MS);
    c.send(QUOTA as u64);
    assert!(refused_for_quota(&c.pool(true).add(envelope(QUOTA as u64))));
}

/// With the gates open the bucket is the day of the next block: the quota
/// used on a past day does not refuse an envelope today, and the quota used
/// today does — and in both cases execution agrees.
#[test]
fn with_the_clock_gates_open_the_bucket_is_the_next_blocks_day() {
    let day = |ms: u64| (ms / 1000 / MESSAGING_DAY_SECONDS) as u32;
    assert_eq!(
        MessagingExecutor::quota_day(&open(), 5, PAST_MS),
        day(PAST_MS)
    );

    // Quota used on a past day: admitted today, and it executes today.
    let mut past = Chain::ready(open(), PAST_MS);
    past.send(QUOTA as u64);
    let e = envelope(QUOTA as u64);
    past.pool(true).add(e.clone()).expect("a new day");
    past.t0 = now_ms() - past.height * MINUTE_MS;
    assert_eq!(past.one(e).status, TxStatus::Success);

    // Quota used today: refused, and it would not execute. Started an hour
    // back so that every block lands before now, and skipped within that hour
    // of midnight so that the blocks and the admission share a day.
    let t0 = now_ms() - 60 * MINUTE_MS;
    if day(t0) != day(now_ms() + 10 * MINUTE_MS) {
        return;
    }
    let mut today = Chain::ready(open(), t0);
    today.send(QUOTA as u64);
    let e = envelope(QUOTA as u64);
    assert!(refused_for_quota(&today.pool(true).add(e.clone())));
    assert!(matches!(
        today.try_block(vec![e]),
        Err(StateError::BlockTransactionAborted { .. })
    ));
}

// ── exact ───────────────────────────────────────────────────────────────────

/// What rule 4 refuses is exactly what execution cannot carry: the refused
/// envelope aborts the block that tries; the last admitted one executes.
#[test]
fn what_is_refused_cannot_execute_and_what_is_admitted_can() {
    let mut c = Chain::ready(closed(), PAST_MS);
    c.send(QUOTA as u64 - 1);
    let last = envelope(QUOTA as u64 - 1);
    c.pool(true).add(last.clone()).expect("admitted");
    assert_eq!(c.one(last).status, TxStatus::Success);

    let over = envelope(QUOTA as u64);
    assert!(refused_for_quota(&c.pool(true).add(over.clone())));
    let height = c.height;
    assert!(matches!(
        c.try_block(vec![over]),
        Err(StateError::BlockTransactionAborted { .. })
    ));
    assert_eq!(c.height, height, "no block");
}
