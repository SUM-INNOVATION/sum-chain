//! SRC-201 messaging executes against the block's candidate.
//!
//! These drive `BlockExecutor::execute_tx` with real signed transactions in
//! sequence, in one block. An accessor test proves an accessor; only a
//! transaction sequence proves that a later transaction observes what an
//! earlier one staged — and for this subsystem that is not a nicety. Three of
//! the reads are guards:
//!
//!   * the sender nonce is replay protection,
//!   * the daily count is the quota,
//!   * the spam score gates the stake requirement,
//!
//! and each was a COMMITTED read that happened to be correct only because the
//! matching write committed as it went. Moving the writes without the reads
//! would have left all three reading pre-block state, which no test that checks
//! where rows land would have caught.

mod common;

use common::{fund, setup_with_params, CHAIN_ID};
use sumchain_crypto::{recipient_hash, sign, KeyPair};
use sumchain_genesis::{ChainParams, MessagingParams};
use sumchain_primitives::messaging::{
    BlockSenderData, ClaimPaymentData, ContactData, ContentType, MessageFlags, MessageHeader,
    MessagingTxData, RegisterPublicKeyData, ReportSpamData, SendMessageData,
    SendMessageWithPaymentData, SetDailyQuotaData, SetInboxFilterData, StakeForTrustData,
    SRC201_MAGIC, SRC201_NONCE_SIZE, SRC201_TAG_SIZE, SRC201_VERSION,
};
use sumchain_primitives::{
    Address, Hash, InboxFilter, MessagingOperation, SignedTransaction, TransactionV2, TxPayload,
    TxStatus,
};
use sumchain_state::MessagingExecutor;
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::messaging_store::{config_keys, decode_inbox_filter, decode_u32, decode_u64};
use sumchain_storage::overlay::ApplicationOverlay;
use sumchain_storage::{cf, Database};

/// Every family this unit moved. Thirteen.
const MESSAGING_CFS: &[&str] = &[
    cf::MESSAGING_CONFIG,
    cf::MESSAGING_SENDER_NONCES,
    cf::MESSAGING_DAILY_COUNTS,
    cf::MESSAGING_STAKES,
    cf::MESSAGING_SPAM_SCORES,
    cf::MESSAGING_INBOX_FILTERS,
    cf::MESSAGING_CONTACTS,
    cf::MESSAGING_BLOCKED,
    cf::MESSAGING_PENDING_PAYMENTS,
    cf::MESSAGING_PAYMENTS_BY_RECIPIENT,
    cf::MESSAGING_EVENTS,
    cf::MESSAGING_SENDER_EVENTS,
    cf::MESSAGING_PUBLIC_KEYS,
];

fn params() -> ChainParams {
    ChainParams::with_v2_enabled()
}

/// The same, with `admin` configured as the GENESIS registry admin, which is
/// the fallback the malformed-row test must prove is not reached.
fn params_with_genesis_admin(admin: &Address) -> ChainParams {
    let mut p = ChainParams::with_v2_enabled();
    p.messaging = Some(MessagingParams {
        registry_admin: Some(admin.to_base58()),
        ..MessagingParams::default()
    });
    p
}

/// The sponsored-registration gate, open from genesis.
fn params_sponsored() -> ChainParams {
    let mut p = ChainParams::with_v2_enabled();
    p.messaging_sponsored_registration_enabled_from_height = Some(0);
    p
}

/// The inner v2 transaction for a sponsored registration, plus the signature
/// and key the v2 surface takes separately.
fn sponsored_register_v2(
    sponsor: &KeyPair,
    registrant: &KeyPair,
    nonce: u64,
) -> (TransactionV2, [u8; 64], [u8; 32]) {
    use sumchain_primitives::messaging::{
        sponsored_register_v1_signing_preimage, RegisterPublicKeySponsoredV1Data,
    };
    let registrant_public_key = *registrant.public_key().as_bytes();
    let preimage = sponsored_register_v1_signing_preimage(
        CHAIN_ID,
        &sponsor.address(),
        &registrant_public_key,
    );
    let reg = RegisterPublicKeySponsoredV1Data {
        registrant_public_key,
        registrant_signature: *sign(&preimage, registrant.private_key()).as_bytes(),
    };
    let data = MessagingTxData {
        operation: MessagingOperation::RegisterPublicKeySponsoredV1,
        data: reg.to_bytes(),
    };
    let tx = TransactionV2::messaging(CHAIN_ID, sponsor.address(), 100, nonce, data);
    let sig = *sign(tx.signing_hash().as_bytes(), sponsor.private_key()).as_bytes();
    (tx, sig, *sponsor.public_key().as_bytes())
}

/// The v2 transaction for a plain messaging operation, in the same shape.
fn messaging_v2(
    kp: &KeyPair,
    nonce: u64,
    data: MessagingTxData,
) -> (TransactionV2, [u8; 64], [u8; 32]) {
    let tx = TransactionV2 {
        chain_id: CHAIN_ID,
        from: kp.address(),
        fee: 100,
        nonce,
        payload: TxPayload::Messaging(data),
    };
    let sig = *sign(tx.signing_hash().as_bytes(), kp.private_key()).as_bytes();
    (tx, sig, *kp.public_key().as_bytes())
}

/// A sponsored registration of `registrant`'s key, paid by `sponsor`, signed
/// the way the dispatch path verifies it.
fn sponsored_register_tx(sponsor: &KeyPair, registrant: &KeyPair, nonce: u64) -> SignedTransaction {
    use sumchain_primitives::messaging::{
        sponsored_register_v1_signing_preimage, RegisterPublicKeySponsoredV1Data,
    };
    let registrant_public_key = *registrant.public_key().as_bytes();
    let preimage = sponsored_register_v1_signing_preimage(
        CHAIN_ID,
        &sponsor.address(),
        &registrant_public_key,
    );
    let reg = RegisterPublicKeySponsoredV1Data {
        registrant_public_key,
        registrant_signature: *sign(&preimage, registrant.private_key()).as_bytes(),
    };
    let data = MessagingTxData {
        operation: MessagingOperation::RegisterPublicKeySponsoredV1,
        data: reg.to_bytes(),
    };
    let tx = TransactionV2::messaging(CHAIN_ID, sponsor.address(), 100, nonce, data);
    let h = tx.signing_hash();
    let sig = sign(h.as_bytes(), sponsor.private_key());
    SignedTransaction::new_v2(tx, *sig.as_bytes(), *sponsor.public_key().as_bytes())
}

fn signed(kp: &KeyPair, nonce: u64, data: MessagingTxData) -> SignedTransaction {
    let tx = TransactionV2 {
        chain_id: CHAIN_ID,
        from: kp.address(),
        fee: 100,
        nonce,
        payload: TxPayload::Messaging(data),
    };
    let h = tx.signing_hash();
    let sig = sign(h.as_bytes(), kp.private_key());
    SignedTransaction::new_v2(tx, *sig.as_bytes(), *kp.public_key().as_bytes())
}

fn msg(op: MessagingOperation, payload: &impl serde::Serialize) -> MessagingTxData {
    MessagingTxData {
        operation: op,
        data: bincode::serialize(payload).unwrap(),
    }
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

fn direct(rh: [u8; 32]) -> MessagingTxData {
    msg(
        MessagingOperation::SendMessageDirect,
        &SendMessageData {
            message_data: valid_message(rh),
            recipient_hash: rh,
        },
    )
}

/// Canonical rows across all thirteen families.
fn canonical(db: &Database) -> Vec<(String, Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    for f in MESSAGING_CFS {
        for (k, v) in db.prefix_iter(f, &[]).unwrap() {
            out.push((f.to_string(), k.to_vec(), v.to_vec()));
        }
    }
    out.sort();
    out
}

/// The same, from the candidate.
fn staged(view: &ExecutionView<'_, '_>) -> Vec<(String, Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    for f in MESSAGING_CFS {
        for item in view.prefix_iter(f, &[]).unwrap() {
            let (k, v) = item.unwrap();
            out.push((f.to_string(), k.to_vec(), v.to_vec()));
        }
    }
    out.sort();
    out
}

/// Which of the thirteen families the candidate has touched.
fn families_staged(view: &ExecutionView<'_, '_>) -> Vec<&'static str> {
    MESSAGING_CFS
        .iter()
        .filter(|f| view.prefix_iter(f, &[]).unwrap().next().is_some())
        .copied()
        .collect()
}

// ── Same-block visibility: the three guards ──────────────────────────────────

/// Two messages from one sender in one block: the second sees the first's
/// nonce and daily count. A third transaction reports spam twice and sees the
/// score accumulate.
///
/// Against committed state all three would reset for every transaction in the
/// block: the same nonce reused, the quota counted from the parent, the spam
/// score never rising within a block.
#[test]
fn a_second_message_in_the_block_sees_the_firsts_counters() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let sender = KeyPair::generate();
    let reporter = KeyPair::generate();
    fund(&db, &sender, 10_000_000);
    fund(&db, &reporter, 500_000_000_000);
    let proposer = Address::new([9; 20]);
    let rh = [7u8; 32];
    let spammer = Address::new([4; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    // A direct send advances the ACCOUNT nonce itself, so these are 0 and 1.
    // Most other messaging operations do not touch it -- the MESSAGING sender
    // nonce below is this subsystem's own replay guard, and it is the one that
    // has to see this block rather than the parent.
    for i in 0..2usize {
        let r = executor
            .execute_tx(
                &mut view,
                &signed(&sender, i as u64, direct(rh)),
                &proposer,
                1,
                1000,
            )
            .unwrap();
        assert!(
            matches!(r.status, TxStatus::Success),
            "send {i} must succeed: {:?}",
            r.status
        );
        let expected = i as u64 + 1;
        assert_eq!(
            MessagingExecutor::v_get_sender_nonce(&view, &sender.address()).unwrap(),
            expected,
            "the messaging nonce must count this block's sends, not the parent's"
        );
        assert_eq!(
            MessagingExecutor::v_get_daily_message_count(&view, &sender.address(), 0).unwrap(),
            expected as u32,
            "and so must the daily quota counter"
        );
    }

    // Spam score: a report requires stake, so the reporter stakes FIRST, in
    // this same block -- which also proves the stake read sees the block.
    let stake = msg(
        MessagingOperation::StakeForTrust,
        &StakeForTrustData {
            amount: 200_000_000_000,
        },
    );
    let rs = executor
        .execute_tx(&mut view, &signed(&reporter, 0, stake), &proposer, 1, 1000)
        .unwrap();
    assert!(
        matches!(rs.status, TxStatus::Success),
        "the stake must succeed: {:?}",
        rs.status
    );

    for i in 0..2usize {
        let report = msg(
            MessagingOperation::ReportSpam,
            &ReportSpamData {
                message_id: Hash::hash(&[i as u8]),
                spammer,
            },
        );
        let r = executor
            .execute_tx(&mut view, &signed(&reporter, 0, report), &proposer, 1, 1000)
            .unwrap();
        assert!(
            matches!(r.status, TxStatus::Success),
            "report {i} must succeed: {:?}",
            r.status
        );
        assert_eq!(
            MessagingExecutor::v_get_spam_score(&view, &spammer).unwrap(),
            (i as u32 + 1) * 5,
            "each report must add to the score this block already holds"
        );
    }

    // And the raw rows say the same thing, through the shared decoders.
    let nonce_row = view
        .get(cf::MESSAGING_SENDER_NONCES, sender.address().as_bytes())
        .unwrap()
        .expect("nonce row staged");
    assert_eq!(decode_u64(&nonce_row, "nonce").unwrap(), 2);
    let mut count_key = sender.address().as_bytes().to_vec();
    count_key.extend_from_slice(&0u32.to_be_bytes());
    let count_row = view
        .get(cf::MESSAGING_DAILY_COUNTS, &count_key)
        .unwrap()
        .expect("count row staged");
    assert_eq!(decode_u32(&count_row, "count").unwrap(), 2);
}

// ── Sponsored registration, and its duplicate check ──────────────────────────

/// A second sponsored registration for the same address fails AS A DUPLICATE,
/// and leaves the first staged key untouched.
///
/// The duplicate check was a committed read, so both would have passed in one
/// block and the second would have overwritten the first.
#[test]
fn a_second_sponsored_registration_in_the_block_fails_as_a_duplicate() {
    let (_state, db, _dir, executor) = setup_with_params(params_sponsored());
    let sponsor = KeyPair::generate();
    let registrant = KeyPair::generate();
    fund(&db, &sponsor, 10_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    let first = sponsored_register_tx(&sponsor, &registrant, 0);
    let r0 = executor
        .execute_tx(&mut view, &first, &proposer, 1, 1000)
        .unwrap();
    assert!(
        matches!(r0.status, TxStatus::Success),
        "the first registration must succeed: {:?}",
        r0.status
    );
    let staged_key = MessagingExecutor::v_get_public_key(&view, &registrant.address())
        .unwrap()
        .expect("the first registration staged a key");

    let second = sponsored_register_tx(&sponsor, &registrant, 1);
    let r1 = executor
        .execute_tx(&mut view, &second, &proposer, 1, 1000)
        .unwrap();
    assert_eq!(
        r1.status,
        TxStatus::Failed(394),
        "the second must fail as a DUPLICATE, not for some other reason: {:?}",
        r1.status
    );
    assert_eq!(
        MessagingExecutor::v_get_public_key(&view, &registrant.address()).unwrap(),
        Some(staged_key),
        "and the first key must be exactly as it was"
    );
}

// ── Two-row writes ───────────────────────────────────────────────────────────

/// A payment writes the primary AND the recipient index; claiming deletes both.
#[test]
fn a_payment_and_its_claim_move_both_rows() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let sender = KeyPair::generate();
    let recipient = KeyPair::generate();
    fund(&db, &sender, 10_000_000);
    let proposer = Address::new([9; 20]);
    let rh = recipient_hash(&recipient.address());

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    let pay = msg(
        MessagingOperation::SendMessageWithPayment,
        &SendMessageWithPaymentData {
            message_data: valid_message(rh),
            recipient_hash: rh,
            koppa_amount: 500,
        },
    );
    let r = executor
        .execute_tx(&mut view, &signed(&sender, 0, pay), &proposer, 1, 1000)
        .unwrap();
    assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);

    let message_id = {
        let rows: Vec<_> = view
            .prefix_iter(cf::MESSAGING_PENDING_PAYMENTS, &[])
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert_eq!(rows.len(), 1, "one primary payment row");
        let mut id = [0u8; 32];
        id.copy_from_slice(&rows[0].0);
        Hash::new(id)
    };
    let index_rows: Vec<_> = view
        .prefix_iter(cf::MESSAGING_PAYMENTS_BY_RECIPIENT, &rh)
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    assert_eq!(index_rows.len(), 1, "and one index row under the recipient");
    assert!(
        index_rows[0].1.is_empty(),
        "the index row carries an EMPTY value"
    );

    let claim = msg(
        MessagingOperation::ClaimPayment,
        &ClaimPaymentData {
            message_id,
            recipient_address: recipient.address(),
        },
    );
    fund(&db, &recipient, 10_000_000);
    let rc = executor
        .execute_tx(&mut view, &signed(&recipient, 0, claim), &proposer, 1, 1000)
        .unwrap();
    assert!(matches!(rc.status, TxStatus::Success), "{:?}", rc.status);

    assert!(
        MessagingExecutor::v_get_pending_payment(&view, &message_id)
            .unwrap()
            .is_none(),
        "the claim must delete the primary row"
    );
    assert!(
        view.prefix_iter(cf::MESSAGING_PAYMENTS_BY_RECIPIENT, &rh)
            .unwrap()
            .next()
            .is_none(),
        "and the index row with it -- deleting one and not the other is the \\
         divergence the batch used to prevent"
    );
}

/// A message event stages the event row and the sender index row, both
/// carrying the whole event.
#[test]
fn publishing_an_event_stages_both_rows() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let sender = KeyPair::generate();
    fund(&db, &sender, 10_000_000);
    let proposer = Address::new([9; 20]);
    let rh = [3u8; 32];

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let r = executor
        .execute_tx(
            &mut view,
            &signed(&sender, 0, direct(rh)),
            &proposer,
            5,
            1000,
        )
        .unwrap();
    assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);

    let events: Vec<_> = view
        .prefix_iter(cf::MESSAGING_EVENTS, &rh)
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    let index: Vec<_> = view
        .prefix_iter(cf::MESSAGING_SENDER_EVENTS, sender.address().as_bytes())
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    assert_eq!(events.len(), 1, "one event row, under the recipient hash");
    assert_eq!(index.len(), 1, "one sender index row");
    assert_eq!(
        events[0].1, index[0].1,
        "the index carries the WHOLE event, byte for byte, not a pointer"
    );
    assert_eq!(
        events[0].0.len(),
        44,
        "recipient_hash(32)||height(8)||tx(4)"
    );
    assert_eq!(index[0].0.len(), 32, "sender(20)||height(8)||tx(4)");
}

// ── Abandonment across all thirteen families ─────────────────────────────────

/// A block that touches every messaging family commits none of it.
///
/// The families are asserted individually before the drop, so "nothing
/// committed" is not satisfied by a block that staged nothing.
#[test]
fn an_abandoned_block_leaves_all_thirteen_families_untouched() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let admin = KeyPair::generate();
    let user = KeyPair::generate();
    let recipient = KeyPair::generate();
    for k in [&admin, &user, &recipient] {
        fund(&db, k, 500_000_000_000);
    }
    // The admin row is set committed, the way genesis or an earlier block
    // would, so the admin-only operations below are authorised.
    sumchain_storage::MessagingStore::new(&db)
        .set_registry_admin(&admin.address())
        .unwrap();
    let before = canonical(&db);
    let proposer = Address::new([9; 20]);
    let rh = recipient_hash(&recipient.address());

    {
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);

        let txs = vec![
            // CONFIG
            (
                &admin,
                0u64,
                msg(
                    MessagingOperation::SetDailyQuota,
                    &SetDailyQuotaData { quota: 99 },
                ),
            ),
            // STAKES
            (
                &user,
                0,
                msg(
                    MessagingOperation::StakeForTrust,
                    &StakeForTrustData {
                        amount: 200_000_000_000,
                    },
                ),
            ),
            // INBOX_FILTERS
            (
                &user,
                0,
                msg(
                    MessagingOperation::SetInboxFilter,
                    &SetInboxFilterData {
                        mode: InboxFilter::ContactsOnly,
                    },
                ),
            ),
            // CONTACTS
            (
                &user,
                0,
                msg(
                    MessagingOperation::AddContact,
                    &ContactData {
                        contact_hash: [8u8; 32],
                    },
                ),
            ),
            // BLOCKED
            (
                &user,
                0,
                msg(
                    MessagingOperation::BlockSender,
                    &BlockSenderData {
                        sender: Address::new([2; 20]),
                    },
                ),
            ),
            // SPAM_SCORES
            (
                &user,
                0,
                msg(
                    MessagingOperation::ReportSpam,
                    &ReportSpamData {
                        message_id: Hash::hash(b"m"),
                        spammer: Address::new([3; 20]),
                    },
                ),
            ),
            // PUBLIC_KEYS
            (
                &user,
                0,
                msg(
                    MessagingOperation::RegisterPublicKey,
                    &RegisterPublicKeyData {
                        public_key: *user.public_key().as_bytes(),
                    },
                ),
            ),
            // NONCES, DAILY_COUNTS, EVENTS, SENDER_EVENTS, PENDING_PAYMENTS,
            // PAYMENTS_BY_RECIPIENT
            (
                &user,
                0,
                msg(
                    MessagingOperation::SendMessageWithPayment,
                    &SendMessageWithPaymentData {
                        message_data: valid_message(rh),
                        recipient_hash: rh,
                        koppa_amount: 250,
                    },
                ),
            ),
        ];
        for (i, (kp, nonce, data)) in txs.into_iter().enumerate() {
            let r = executor
                .execute_tx(&mut view, &signed(kp, nonce, data), &proposer, 1, 1000)
                .unwrap();
            assert!(
                matches!(r.status, TxStatus::Success),
                "seeding transaction {i} must succeed: {:?}",
                r.status
            );
        }

        // All thirteen, individually. A family missing here would make the
        // assertion after the drop vacuous for that family.
        let touched = families_staged(&view);
        for f in MESSAGING_CFS {
            assert!(
                touched.contains(f),
                "{f} was not staged, so dropping the block proves nothing about it"
            );
        }
        assert_ne!(
            staged(&view),
            before,
            "and the staged set must differ from canonical"
        );
        // dropped
    }

    assert_eq!(
        canonical(&db),
        before,
        "an abandoned block must leave every messaging row byte-identical"
    );
}

// ── Limit refusal ────────────────────────────────────────────────────────────

/// A refusal part-way leaves canonical storage untouched, with at least one
/// write already staged when it happens.
#[test]
fn a_refusal_part_way_leaves_canonical_storage_untouched() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let user = KeyPair::generate();
    fund(&db, &user, 100_000_000);
    let before = canonical(&db);
    let proposer = Address::new([9; 20]);
    let rh = [6u8; 32];
    let tx = signed(&user, 0, direct(rh));

    // What the whole transaction costs.
    let full = {
        let mut scratch = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        {
            let mut view = ExecutionView::new(&mut scratch);
            executor
                .execute_tx(&mut view, &tx, &proposer, 1, 1000)
                .unwrap();
        }
        scratch.logical_bytes()
    };

    // Walk ceilings down from one byte short until the refusal lands with
    // something already staged. The exact byte is not stable across fee
    // changes; that at least one exists is the property.
    let mut saw_partial = false;
    for ceiling in (1..full).rev().step_by(((full / 40).max(1)) as usize) {
        let mut overlay = ApplicationOverlay::new(&db, ceiling);
        let mut view = ExecutionView::new(&mut overlay);
        let outcome = executor.execute_tx(&mut view, &tx, &proposer, 1, 1000);
        assert!(outcome.is_err(), "ceiling {ceiling} must refuse");
        let err = outcome.unwrap_err().to_string();
        assert!(
            err.contains("limit"),
            "it must fail because a WRITE was refused: {err}"
        );
        if !families_staged(&view).is_empty() {
            saw_partial = true;
        }
        assert_eq!(
            canonical(&db),
            before,
            "a refusal at ceiling {ceiling} must leave canonical storage as it was"
        );
    }
    assert!(
        saw_partial,
        "at least one ceiling must refuse AFTER a messaging write has been \\
         staged -- otherwise this only covers refusal before the first write"
    );
}

// ── Inbox decoding ───────────────────────────────────────────────────────────

/// Every byte the filter column can hold, including the ones it should not.
///
/// The expectations are LITERAL variants, not the output of either decoder: an
/// expectation computed from one of the implementations cannot distinguish them.
///
/// Note what this can and cannot prove. `InboxFilter::from_byte` maps 0/1/2 and
/// returns `None` otherwise, and the hand-written mapping the candidate reader
/// used in an earlier draft (`Some(1) => ContactsOnly, Some(2) => StakedOnly,
/// _ => AcceptAll`) is observationally IDENTICAL for all 256 byte values. So no
/// behavioural test can separate them today; they diverge only when a fourth
/// variant is added, silently. That claim is structural, and
/// `the_candidate_filter_reader_delegates_to_the_shared_decoder` below is what
/// pins it.
#[test]
fn inbox_filter_decoding_covers_every_byte() {
    assert_eq!(decode_inbox_filter(&[0]), InboxFilter::AcceptAll);
    assert_eq!(decode_inbox_filter(&[1]), InboxFilter::ContactsOnly);
    assert_eq!(decode_inbox_filter(&[2]), InboxFilter::StakedOnly);
    assert_eq!(
        decode_inbox_filter(&[3]),
        InboxFilter::AcceptAll,
        "an unknown byte reads as AcceptAll, as the committed reader did"
    );
    assert_eq!(
        decode_inbox_filter(&[]),
        InboxFilter::AcceptAll,
        "and so does an empty value"
    );

    // And the candidate reader, against the same literals.
    let dir = tempfile::TempDir::new().unwrap();
    let db = std::sync::Arc::new(Database::open_default(dir.path()).unwrap());
    let rh = [1u8; 32];
    for (bytes, expected) in [
        (vec![0u8], InboxFilter::AcceptAll),
        (vec![1], InboxFilter::ContactsOnly),
        (vec![2], InboxFilter::StakedOnly),
        (vec![3], InboxFilter::AcceptAll),
        (vec![], InboxFilter::AcceptAll),
    ] {
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);
        view.put(cf::MESSAGING_INBOX_FILTERS, &rh, &bytes).unwrap();
        assert_eq!(
            MessagingExecutor::v_get_inbox_filter(&view, &rh).unwrap(),
            expected,
            "the candidate reader must return {expected:?} for {bytes:?}"
        );
    }
}

/// The candidate filter reader DELEGATES; it does not carry its own mapping.
///
/// The behavioural test above cannot see the difference, because the two
/// mappings agree on every byte that exists today. What separates them is a
/// future variant, so the guard is structural: this file must call the shared
/// decoder and must not match on `InboxFilter` variants itself. The same shape
/// as the contract commit-point guard, and for the same reason -- a divergence
/// that no input can currently expose still has to be prevented.
#[test]
fn the_candidate_filter_reader_delegates_to_the_shared_decoder() {
    let src = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/messaging_view.rs"),
    )
    .expect("messaging_view.rs");
    // Comments are not code: a comment naming the mapping must not read as one.
    let code: String = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");

    assert!(
        code.contains("decode_inbox_filter"),
        "the candidate reader must call the shared decoder"
    );
    for variant in ["InboxFilter::ContactsOnly", "InboxFilter::StakedOnly"] {
        assert!(
            !code.contains(variant),
            "messaging_view.rs names {variant}, which means it is deciding the \
             mapping itself instead of delegating -- the two agree today and \
             would diverge the day a variant is added"
        );
    }
}

// ── The admin predicate ──────────────────────────────────────────────────────

/// A malformed registry-admin row fails the operation, stages nothing, and does
/// NOT fall back to the genesis admin.
///
/// The old predicate was `-> bool` around `if let Ok(Some(admin))`, so a decode
/// failure landed in the same branch as "no admin configured" and the genesis
/// address took over. A corrupt twenty-first byte moved authority.
#[test]
fn a_malformed_admin_row_fails_the_operation_and_skips_the_genesis_fallback() {
    let genesis_admin = KeyPair::generate();
    let (_state, db, _dir, executor) =
        setup_with_params(params_with_genesis_admin(&genesis_admin.address()));
    fund(&db, &genesis_admin, 10_000_000);
    let proposer = Address::new([9; 20]);

    // A stored admin value of the wrong length: the decoder refuses it.
    db.put(
        cf::MESSAGING_CONFIG,
        config_keys::REGISTRY_ADMIN,
        &[1u8; 19],
    )
    .unwrap();
    let before = canonical(&db);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    {
        let mut view = ExecutionView::new(&mut overlay);
        let quota = msg(
            MessagingOperation::SetDailyQuota,
            &SetDailyQuotaData { quota: 42 },
        );
        // Sent BY the genesis admin: if the fallback were reached, this would
        // succeed.
        let outcome = executor.execute_tx(
            &mut view,
            &signed(&genesis_admin, 0, quota),
            &proposer,
            1,
            1000,
        );

        assert!(
            outcome.is_err(),
            "a malformed admin row must fail the transaction, not be read as \\
         'no admin configured'"
        );

        // No protected config change staged: the quota key is untouched.
        assert_eq!(
            view.get(cf::MESSAGING_CONFIG, config_keys::DAILY_QUOTA)
                .unwrap(),
            None,
            "the protected write must not have been staged"
        );
    }
    assert_eq!(
        canonical(&db),
        before,
        "and nothing may be committed either"
    );
}

// ── Both dispatch surfaces ───────────────────────────────────────────────────

/// `execute_tx_v2` routes messaging through the candidate too, sponsored
/// registration included.
///
/// There are two public transaction surfaces. `execute_tx` (which wraps
/// `execute_tx_with_validators`) is the live one and every test above drives
/// it; `execute_tx_v2` is `pub` with no production caller, and it has its own
/// messaging arm AND its own sponsored-registration interception
/// (`executor.rs:2428`). A migration that moved only the live arm would leave
/// the other writing committed rows, and the closure ledger -- which reaches
/// both -- would have refused the row removal. This drives the second surface
/// directly so the claim rests on a test rather than on the ledger alone.
#[test]
fn the_v2_dispatch_surface_also_stages_messaging_and_sponsored_registration() {
    let (_state, db, _dir, executor) = setup_with_params(params_sponsored());
    let sender = KeyPair::generate();
    let sponsor = KeyPair::generate();
    let registrant = KeyPair::generate();
    fund(&db, &sender, 10_000_000);
    fund(&db, &sponsor, 10_000_000);
    let proposer = Address::new([9; 20]);
    let rh = [11u8; 32];
    let before = canonical(&db);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    {
        let mut view = ExecutionView::new(&mut overlay);

        // A plain send, through the v2 surface.
        let (send, send_sig, send_key) = messaging_v2(&sender, 0, direct(rh));
        let r = executor
            .execute_tx_v2(
                &mut view, &send, &send_sig, &send_key, &proposer, 1, 1000, 0,
            )
            .unwrap();
        assert!(
            matches!(r.status, TxStatus::Success),
            "the v2 surface must execute a messaging send: {:?}",
            r.status
        );
        assert!(
            view.prefix_iter(cf::MESSAGING_EVENTS, &rh)
                .unwrap()
                .next()
                .is_some(),
            "and stage its event"
        );

        // And the sponsored registration it intercepts.
        let (reg, reg_sig, reg_key) = sponsored_register_v2(&sponsor, &registrant, 0);
        let rr = executor
            .execute_tx_v2(&mut view, &reg, &reg_sig, &reg_key, &proposer, 1, 1000, 0)
            .unwrap();
        assert!(
            matches!(rr.status, TxStatus::Success),
            "the v2 surface must execute a sponsored registration: {:?}",
            rr.status
        );
        assert!(
            MessagingExecutor::v_get_public_key(&view, &registrant.address())
                .unwrap()
                .is_some(),
            "and stage the registrant's key"
        );
    }
    assert_eq!(
        canonical(&db),
        before,
        "neither may commit while the block is being built"
    );
}

// ── TS-10's tx_index half, and TS-11, on the messaging arm ──────────────────
//
// Messaging keys its event rows `recipient_hash(32) || height(8) || tx_index(4)`
// and its sender index `sender(20) || height(8) || tx_index(4)`. With `tx_index`
// a literal zero, two messages sent to one recipient in one block are one row,
// and the earlier one is gone — the same data-destroying collision TS-10 names
// on DocClass, on a family that is a user's inbox.
//
// The timestamp is the separate defect TS-11 records, behind the separate gate
// `subsystem_block_timestamp_enabled_from_height`: below it `MessageEvent`
// carries `timestamp: 0`, the daily-quota bucket is day zero for the life of the
// chain, and a pending payment's expiry is compared against the epoch.

/// `params()`, with the transaction-index gate open from genesis.
fn params_tx_index_enabled() -> ChainParams {
    let mut p = params();
    p.subsystem_tx_index_enabled_from_height = Some(0);
    p
}

/// `params()`, with the block-timestamp gate open from genesis.
fn params_block_timestamp_enabled() -> ChainParams {
    let mut p = params();
    p.subsystem_block_timestamp_enabled_from_height = Some(0);
    p
}

/// Two direct messages from one sender to one recipient, in one block at
/// `height`, each given its own transaction index. Returns the event rows the
/// candidate holds under that recipient, in key order.
fn two_messages_to_one_recipient(
    p: ChainParams,
    height: u64,
    block_timestamp: u64,
) -> Vec<(Vec<u8>, sumchain_primitives::MessageEvent)> {
    let (_state, db, _dir, executor) = setup_with_params(p);
    let sender = KeyPair::generate();
    fund(&db, &sender, 10_000_000);
    let proposer = Address::new([9; 20]);
    let rh = [3u8; 32];

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    for nonce in 0..2u64 {
        let r = executor
            .execute_tx_with_validators(
                &mut view,
                &signed(&sender, nonce, direct(rh)),
                &proposer,
                height,
                block_timestamp,
                nonce as u32,
                &[],
            )
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    }

    view.prefix_iter(cf::MESSAGING_EVENTS, &rh)
        .unwrap()
        .map(|r| {
            let (k, v) = r.unwrap();
            (
                k.to_vec(),
                sumchain_storage::messaging_store::decode_message_event(&v).unwrap(),
            )
        })
        .collect()
}

/// The key `recipient_hash || height || tx_index`, as the store builds it.
fn messaging_event_key(rh: &[u8; 32], height: u64, tx_index: u32) -> Vec<u8> {
    let mut k = rh.to_vec();
    k.extend_from_slice(&height.to_be_bytes());
    k.extend_from_slice(&tx_index.to_be_bytes());
    k
}

/// At the gate, two messages to one recipient in one block are two rows.
#[test]
fn two_messages_to_one_recipient_in_a_block_land_at_two_keys_at_the_gate() {
    let rows = two_messages_to_one_recipient(params_tx_index_enabled(), 5, 1000);
    let rh = [3u8; 32];
    assert_eq!(rows.len(), 2, "two messages, two rows");
    assert_eq!(
        rows.iter().map(|(k, _)| k.clone()).collect::<Vec<_>>(),
        vec![
            messaging_event_key(&rh, 5, 0),
            messaging_event_key(&rh, 5, 1),
        ],
        "keyed by the transaction's own index within the block"
    );
    assert_ne!(
        rows[0].1.message_id, rows[1].1.message_id,
        "and they are two DIFFERENT messages, not one written twice"
    );
}

/// Below the gate the same two messages, given their REAL indices, are one row.
///
/// The discriminator: real indices go in, one row comes out, so what decides is
/// `subsystem_tx_index_enabled_from_height` and not the caller.
#[test]
fn the_same_two_messages_still_collide_below_the_gate() {
    assert_eq!(
        params().subsystem_tx_index_enabled_from_height,
        None,
        "the fixture must be the dormant one"
    );
    let rows = two_messages_to_one_recipient(params(), 5, 1000);
    assert_eq!(rows.len(), 1, "two messages, one row -- unchanged");
    assert_eq!(rows[0].0, messaging_event_key(&[3u8; 32], 5, 0));
}

/// TS-11: a messaging event is stamped at time zero until the timestamp gate.
///
/// The messaging arm was handed `0, // block_timestamp placeholder` by both
/// dispatch arms, so this was not a mis-stamp alone: `current_day` buckets the
/// daily quota by this value, and at the epoch every message a chain ever sends
/// counts against day zero.
///
/// Two directions from one fixture, and the discriminator is the GATE — the same
/// real block timestamp is passed in both cases.
#[test]
fn a_messaging_event_stamps_a_real_time_only_at_the_gate() {
    const TS: u64 = 1_700_000_000;
    assert_eq!(
        params().subsystem_block_timestamp_enabled_from_height,
        None,
        "the dormant fixture must be dormant"
    );

    let closed = two_messages_to_one_recipient(params(), 5, TS);
    assert_eq!(
        closed[0].1.timestamp, 0,
        "below the gate the executor writes the epoch, whatever the block says"
    );

    let open = two_messages_to_one_recipient(params_block_timestamp_enabled(), 5, TS);
    assert_eq!(
        open[0].1.timestamp, TS,
        "at the gate it writes the block's own timestamp"
    );
}
