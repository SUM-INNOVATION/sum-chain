//! #278: messaging read a millisecond block timestamp as seconds.
//!
//! The block timestamp is milliseconds since the Unix epoch
//! (`BlockHeader::timestamp`, built with `as_millis()` by the proposer). The
//! messaging executor applied three rules to it that are written in seconds:
//!
//!   * the daily-quota bucket, `timestamp / MESSAGING_DAY_SECONDS`;
//!   * a pending payment's expiry, `timestamp + PENDING_PAYMENT_EXPIRY`, later
//!     compared against the claiming block's timestamp;
//!   * a sponsored message's `expiry`, which the client signs in Unix SECONDS
//!     (`messaging_submitSponsored` checks it against `as_secs()`).
//!
//! While `subsystem_block_timestamp_enabled_from_height` is closed the
//! executor sees a timestamp of zero, so none of the three moves. Once it opens
//! the quota window is 86.4 seconds, a payment expires about ten minutes after
//! it is sent, and every sponsored message is already expired.
//!
//! `messaging_timestamp_units_enabled_from_height` reads the timestamp in
//! seconds for those three rules. Each scenario below runs three ways:
//!
//!   * DORMANT     -- today's release configuration, both gates closed;
//!   * DEFECT      -- the block-timestamp gate open, the units gate closed,
//!                    which is exactly what opening the first gate alone does;
//!   * CORRECTED   -- both open.

use sumchain_crypto::recipient_hash;
use sumchain_genesis::ChainParams;
use sumchain_primitives::messaging::{
    ClaimPaymentData, ContentType, MessageFlags, MessageHeader, MessagingTxData,
    RegisterPublicKeyData, SendMessageData, SendMessageWithPaymentData, SRC201_MAGIC,
    SRC201_NONCE_SIZE, SRC201_TAG_SIZE, SRC201_VERSION,
};
use sumchain_primitives::{Address, Hash, MessagingOperation, SponsoredMessage};
use sumchain_state::messaging_executor::{
    MessagingExecutionResult, MESSAGING_DAY_SECONDS, PENDING_PAYMENT_EXPIRY,
};
use sumchain_state::MessagingExecutor;
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::overlay::ApplicationOverlay;
use sumchain_storage::Database;
use tempfile::TempDir;

/// 2025-10-09T08:53:20Z in MILLISECONDS -- a block timestamp as the proposer
/// writes one. 32,000 seconds into its UTC day, so two minutes later is the
/// same calendar day.
const T_MS: u64 = 1_760_000_000_000;
const MINUTE_MS: u64 = 60_000;
const DAY_MS: u64 = 86_400_000;
const HEIGHT: u64 = 10;

fn dormant() -> ChainParams {
    ChainParams::with_v2_enabled()
}

fn defect() -> ChainParams {
    let mut p = dormant();
    p.subsystem_block_timestamp_enabled_from_height = Some(0);
    p
}

fn corrected() -> ChainParams {
    let mut p = defect();
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

fn open_db() -> (Database, TempDir) {
    let dir = TempDir::new().unwrap();
    let db = Database::open_default(dir.path()).unwrap();
    (db, dir)
}

/// Seed `addr` with a balance on the candidate.
fn credit(view: &mut ExecutionView<'_, '_>, addr: &Address, amount: u128) {
    sumchain_state::StateManager::v_credit(view, addr, amount).unwrap();
}

/// One messaging operation in a block at `HEIGHT` and `ts`.
fn run(
    view: &mut ExecutionView<'_, '_>,
    params: &ChainParams,
    sender: &Address,
    data: &MessagingTxData,
    ts: u64,
    tx_tag: u8,
) -> sumchain_state::Result<MessagingExecutionResult> {
    run_at(view, params, sender, data, HEIGHT, ts, tx_tag)
}

/// One messaging operation in a block at `height` and `ts`.
fn run_at(
    view: &mut ExecutionView<'_, '_>,
    params: &ChainParams,
    sender: &Address,
    data: &MessagingTxData,
    height: u64,
    ts: u64,
    tx_tag: u8,
) -> sumchain_state::Result<MessagingExecutionResult> {
    MessagingExecutor::execute(
        view,
        params,
        sender,
        data,
        &Address::new([9; 20]),
        100,
        height,
        ts,
        0,
        Hash::hash(&[tx_tag]),
    )
}

// ── the daily quota ──────────────────────────────────────────────────────────

/// A sender with a quota of ONE sends at `T_MS`, then again at `second_ts`.
/// Returns whether the second send was admitted and the bucket the first used.
fn quota_of_one(params: &ChainParams, second_ts: u64) -> (bool, u32) {
    let (db, _dir) = open_db();
    let mut overlay = ApplicationOverlay::new(&db, 1 << 24);
    let mut view = ExecutionView::new(&mut overlay);
    let sender = Address::new([1; 20]);
    credit(&mut view, &sender, 10_000_000);
    MessagingExecutor::v_set_daily_quota(&mut view, 1).unwrap();
    let rh = [3u8; 32];
    let send = op(
        MessagingOperation::SendMessageDirect,
        &SendMessageData {
            message_data: valid_message(rh),
            recipient_hash: rh,
        },
    );

    let first = run(&mut view, params, &sender, &send, T_MS, 1).unwrap();
    assert!(
        first.success,
        "the first send is within quota: {:?}",
        first.error
    );
    // The three buckets the first send could have landed in: the epoch, the
    // millisecond-over-86,400 bucket, and the UTC day.
    let bucket = [0u32, (T_MS / 86_400) as u32, (T_MS / DAY_MS) as u32]
        .into_iter()
        .find(|day| {
            MessagingExecutor::v_get_daily_message_count(&view, &sender, *day).unwrap() == 1
        })
        .expect("the first send was counted in no bucket this test knows");

    let second = run(&mut view, params, &sender, &send, second_ts, 2);
    let admitted = match second {
        Ok(r) => r.success,
        Err(e) => {
            assert!(
                e.to_string().contains("Daily quota exceeded"),
                "the only refusal expected here is the quota: {e}"
            );
            false
        }
    };
    (admitted, bucket)
}

/// DORMANT: every send counts against day zero, and the quota never resets.
#[test]
fn dormant_the_quota_is_day_zero_forever() {
    let p = dormant();
    assert_eq!(p.subsystem_block_timestamp_enabled_from_height, None);
    assert_eq!(p.messaging_timestamp_units_enabled_from_height, None);

    assert_eq!(quota_of_one(&p, T_MS + 2 * MINUTE_MS), (false, 0));
    assert_eq!(
        quota_of_one(&p, T_MS + 30 * DAY_MS),
        (false, 0),
        "a month later the sender is still refused: today's behaviour, unchanged"
    );
}

/// DEFECT: with the timestamp real and read as seconds, a "day" is 86.4 s.
#[test]
fn defect_the_quota_window_is_eighty_six_seconds() {
    let (admitted, bucket) = quota_of_one(&defect(), T_MS + 2 * MINUTE_MS);
    assert_eq!(
        bucket,
        (T_MS / MESSAGING_DAY_SECONDS) as u32,
        "the bucket is milliseconds over 86,400: {} rather than day {}",
        T_MS / MESSAGING_DAY_SECONDS,
        T_MS / DAY_MS
    );
    assert_eq!(bucket, 20_370_370);
    assert!(
        admitted,
        "two minutes later is a new 'day', so a quota of one admits a second send"
    );
}

/// CORRECTED: the bucket is the UTC day, and it resets a day later.
#[test]
fn corrected_the_quota_window_is_one_day() {
    let (admitted, bucket) = quota_of_one(&corrected(), T_MS + 2 * MINUTE_MS);
    assert_eq!(bucket, (T_MS / DAY_MS) as u32);
    assert_eq!(bucket, 20_370, "days since the epoch");
    assert!(
        !admitted,
        "two minutes later is the same day; quota of one refuses"
    );

    let (admitted, _) = quota_of_one(&corrected(), T_MS + DAY_MS);
    assert!(admitted, "a day later the quota has reset");
}

/// The units gate changes nothing while the block-timestamp gate is closed:
/// zero milliseconds is zero seconds.
#[test]
fn the_units_gate_alone_is_inert() {
    let mut p = dormant();
    p.messaging_timestamp_units_enabled_from_height = Some(0);
    assert_eq!(quota_of_one(&p, T_MS + 30 * DAY_MS), (false, 0));
    assert_eq!(payment_then_claim(&p, T_MS + 30 * DAY_MS), (604_800, true));
}

// ── the pending-payment expiry ──────────────────────────────────────────────

/// A payment sent at `T_MS`, claimed at `claim_ts`. Returns the expiry it was
/// stored with and whether the claim paid the recipient.
fn payment_then_claim(params: &ChainParams, claim_ts: u64) -> (u64, bool) {
    let (db, _dir) = open_db();
    let mut overlay = ApplicationOverlay::new(&db, 1 << 24);
    let mut view = ExecutionView::new(&mut overlay);
    let sender = Address::new([1; 20]);
    let recipient = Address::new([2; 20]);
    credit(&mut view, &sender, 10_000_000);
    credit(&mut view, &recipient, 10_000_000);
    let rh = recipient_hash(&recipient);

    let pay = op(
        MessagingOperation::SendMessageWithPayment,
        &SendMessageWithPaymentData {
            message_data: valid_message(rh),
            recipient_hash: rh,
            koppa_amount: 500,
        },
    );
    let sent = run(&mut view, params, &sender, &pay, T_MS, 1).unwrap();
    assert!(sent.success, "{:?}", sent.error);
    let message_id = Hash::hash(&[1]);
    let expiry = MessagingExecutor::v_get_pending_payment(&view, &message_id)
        .unwrap()
        .expect("payment escrowed")
        .expiry;

    let claim = op(
        MessagingOperation::ClaimPayment,
        &ClaimPaymentData {
            message_id,
            recipient_address: recipient,
        },
    );
    let claimed = run(&mut view, params, &recipient, &claim, claim_ts, 2).unwrap();
    if !claimed.success {
        assert_eq!(
            claimed.error.as_deref(),
            Some("Payment expired, refunded to sender"),
            "the only failure expected here is expiry"
        );
    }
    (expiry, claimed.success)
}

/// DORMANT: the expiry is 604,800 -- a week after the epoch -- and the claim,
/// made "at time zero", always succeeds.
#[test]
fn dormant_payment_expiry_is_a_week_after_the_epoch() {
    assert_eq!(
        payment_then_claim(&dormant(), T_MS + 30 * DAY_MS),
        (PENDING_PAYMENT_EXPIRY, true)
    );
}

/// DEFECT: a week of SECONDS added to MILLISECONDS is ten minutes and 4.8
/// seconds, and a claim eleven minutes later is refunded as expired.
#[test]
fn defect_payment_expires_ten_minutes_after_it_is_sent() {
    let (expiry, _) = payment_then_claim(&defect(), T_MS + MINUTE_MS);
    assert_eq!(expiry, T_MS + 604_800, "a millisecond deadline");
    assert_eq!(expiry - T_MS, 604_800, "604,800 ms = 10 min 4.8 s");

    let (_, paid) = payment_then_claim(&defect(), T_MS + 11 * MINUTE_MS);
    assert!(
        !paid,
        "eleven minutes on, a 'seven-day' payment is refunded"
    );
}

/// CORRECTED: the expiry is Unix seconds plus a week, and the week holds.
#[test]
fn corrected_payment_expires_seven_days_after_it_is_sent() {
    let (expiry, paid) = payment_then_claim(&corrected(), T_MS + 11 * MINUTE_MS);
    assert_eq!(expiry, T_MS / 1000 + PENDING_PAYMENT_EXPIRY, "Unix seconds");
    assert_eq!(expiry, 1_760_604_800);
    assert!(paid, "eleven minutes on the payment is claimable");

    let (_, paid) = payment_then_claim(&corrected(), T_MS + 7 * DAY_MS);
    assert!(
        paid,
        "at exactly seven days it is still claimable (strict >)"
    );
    let (_, paid) = payment_then_claim(&corrected(), T_MS + 7 * DAY_MS + 1_000);
    assert!(!paid, "one second past seven days it is refunded");
}

// ── the sponsored message expiry ────────────────────────────────────────────

/// A sponsored message, expiring in Unix SECONDS at `expiry_secs`, relayed in a
/// block at `ts`. Returns the executor's verdict.
fn sponsored(params: &ChainParams, ts: u64, expiry_secs: u64) -> MessagingExecutionResult {
    let (db, _dir) = open_db();
    let mut overlay = ApplicationOverlay::new(&db, 1 << 24);
    let mut view = ExecutionView::new(&mut overlay);
    MessagingExecutor::v_set_sponsorship_enabled(&mut view, true).unwrap();

    let sender_pubkey = [7u8; 32];
    let real_sender = Address::from_public_key(&sender_pubkey);
    let reg = op(
        MessagingOperation::RegisterPublicKey,
        &RegisterPublicKeyData {
            public_key: sender_pubkey,
        },
    );
    let r = run(&mut view, params, &real_sender, &reg, ts, 1).unwrap();
    assert!(r.success, "{:?}", r.error);

    let rh = [3u8; 32];
    let msg = SponsoredMessage {
        message_data: valid_message(rh),
        recipient_hash: rh,
        signature: [0u8; 64],
        sender_pubkey,
        nonce: 0,
        expiry: expiry_secs,
        koppa_amount: None,
    };
    let send = op(MessagingOperation::SendMessage, &msg);
    let sponsor = Address::new([5; 20]);
    run(&mut view, params, &sponsor, &send, ts, 2).unwrap()
}

/// DEFECT: an expiry an hour ahead in seconds is "behind" any millisecond
/// timestamp, so every sponsored message is refused as expired.
#[test]
fn defect_every_sponsored_message_is_already_expired() {
    let r = sponsored(&defect(), T_MS, T_MS / 1000 + 3600);
    assert!(!r.success);
    assert_eq!(r.error.as_deref(), Some("Sponsored message has expired"));
}

/// DORMANT: compared against zero, nothing ever expires.
#[test]
fn dormant_no_sponsored_message_expires() {
    let r = sponsored(&dormant(), T_MS, 1);
    assert!(r.success, "{:?}", r.error);
}

/// CORRECTED: compared in seconds, an hour ahead is accepted and a second
/// behind is refused.
#[test]
fn corrected_sponsored_expiry_is_compared_in_seconds() {
    let r = sponsored(&corrected(), T_MS, T_MS / 1000 + 3600);
    assert!(r.success, "{:?}", r.error);
    let r = sponsored(&corrected(), T_MS, T_MS / 1000 - 1);
    assert_eq!(r.error.as_deref(), Some("Sponsored message has expired"));
}

// ── the activation boundary ─────────────────────────────────────────────────

/// With the units gate at `HEIGHT`, a payment escrowed one block below it is
/// stored with today's millisecond expiry, and one escrowed at it with the
/// seconds expiry. The height decides, not the caller.
#[test]
fn the_units_gate_takes_effect_exactly_at_its_height() {
    let mut p = defect();
    p.messaging_timestamp_units_enabled_from_height = Some(HEIGHT);

    let (db, _dir) = open_db();
    let mut overlay = ApplicationOverlay::new(&db, 1 << 24);
    let mut view = ExecutionView::new(&mut overlay);
    let sender = Address::new([1; 20]);
    credit(&mut view, &sender, 10_000_000);
    let rh = recipient_hash(&Address::new([2; 20]));
    let pay = op(
        MessagingOperation::SendMessageWithPayment,
        &SendMessageWithPaymentData {
            message_data: valid_message(rh),
            recipient_hash: rh,
            koppa_amount: 500,
        },
    );

    let below = run_at(&mut view, &p, &sender, &pay, HEIGHT - 1, T_MS, 1).unwrap();
    assert!(below.success, "{:?}", below.error);
    let at = run_at(&mut view, &p, &sender, &pay, HEIGHT, T_MS, 2).unwrap();
    assert!(at.success, "{:?}", at.error);

    let expiry = |tag: u8| {
        MessagingExecutor::v_get_pending_payment(&view, &Hash::hash(&[tag]))
            .unwrap()
            .expect("escrowed")
            .expiry
    };
    assert_eq!(expiry(1), T_MS + PENDING_PAYMENT_EXPIRY, "below: unchanged");
    assert_eq!(
        expiry(2),
        T_MS / 1000 + PENDING_PAYMENT_EXPIRY,
        "at: seconds"
    );
}

/// The recorded times are not converted: an event row keeps the block's own
/// millisecond timestamp on either side of the units gate.
#[test]
fn the_event_row_keeps_the_block_timestamp() {
    for p in [defect(), corrected()] {
        let (db, _dir) = open_db();
        let mut overlay = ApplicationOverlay::new(&db, 1 << 24);
        let mut view = ExecutionView::new(&mut overlay);
        let sender = Address::new([1; 20]);
        credit(&mut view, &sender, 10_000_000);
        let rh = [3u8; 32];
        let send = op(
            MessagingOperation::SendMessageDirect,
            &SendMessageData {
                message_data: valid_message(rh),
                recipient_hash: rh,
            },
        );
        let r = run(&mut view, &p, &sender, &send, T_MS, 1).unwrap();
        assert!(r.success, "{:?}", r.error);
        let (_, v) = view
            .prefix_iter(sumchain_storage::cf::MESSAGING_EVENTS, &rh)
            .unwrap()
            .next()
            .expect("an event row")
            .unwrap();
        let event = sumchain_storage::messaging_store::decode_message_event(&v).unwrap();
        assert_eq!(event.timestamp, T_MS);
    }
}
