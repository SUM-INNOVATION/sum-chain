//! Messaging: the committed store and the shared helpers agree byte-for-byte.
//!
//! Preparation for the routing commit. Every key builder and every codec the
//! candidate side will call is the one the committed store already calls; this
//! file pins that with bytes rather than round-trips.
//!
//! ## Why LITERAL bytes, and not a round-trip — or the helper's own output
//!
//! `decode(encode(v)) == v` passes for ANY self-consistent codec. It would
//! still pass if the candidate wrote a daily count as bincode while the chain
//! wrote four big-endian bytes: each side reads back what it wrote, and the two
//! disagree only about rows the other produced — which is exactly what a
//! candidate is, and exactly the case no test that owns both ends constructs.
//!
//! Comparing the stored row against `encode_u32(7)` has the same hole, one
//! level up. The store CALLS that helper, so both sides of the assertion move
//! together: the first version of this file did exactly that, and a mutation
//! flipping `encode_u32` to little-endian passed all ten tests. The widths, the
//! byte order and the presence bytes are written out as literals below for that
//! reason. The helpers appear only where the subject is "the store calls the
//! shared one" (the bincode values), and those are pinned by their key layout
//! and by a decode through the shared reader.
//!
//! ## The three shapes that are easy to get wrong here
//!
//! * WIDTHS DIFFER between adjacent families. A sender nonce is 8 bytes, a
//!   daily count is 4, a stake is 16. All three are "a counter for an address".
//!   The balance cases deliberately use a value ABOVE `u64::MAX`: with a small
//!   value, a sixteen-byte encoding whose high eight bytes are zero is
//!   byte-identical to a narrowed one, and a mutation narrowing `encode_balance`
//!   to eight significant bytes passed this file until the values changed.
//! * ABSENCE IS NOT ZERO. Stakes and spam scores DELETE the row at zero rather
//!   than storing zeroes, so the candidate has to reproduce the deletion or an
//!   abandoned block's rollback restores the wrong shape.
//! * PRESENCE ROWS carry different bytes. Contacts and blocks carry `[1]`; the
//!   recipient-payment index carries an EMPTY value. Writing `[1]` into the
//!   index would round-trip and diverge.

use sumchain_primitives::{
    Address, Hash, InboxFilter, MessageEvent, PendingPayment, RegisteredPublicKey,
};
use sumchain_storage::db::{cf, Database};
use sumchain_storage::messaging_store::config_keys;
use sumchain_storage::messaging_store::{
    blocked_key, contact_key, daily_count_key, decode_message_event, decode_pending_payment,
    decode_public_key, encode_balance, encode_bool, encode_inbox_filter, encode_message_event,
    encode_pending_payment, encode_public_key, encode_u32, encode_u64, event_key, inbox_filter_key,
    payment_index_key, pending_payment_key, public_key_key, sender_index_key, sender_nonce_key,
    spam_score_key, stake_key, INDEX_PRESENT, PRESENT,
};
use sumchain_storage::MessagingStore;
use tempfile::TempDir;

fn db() -> (Database, TempDir) {
    let dir = TempDir::new().unwrap();
    let db = Database::open_default(dir.path()).unwrap();
    (db, dir)
}

fn addr(b: u8) -> Address {
    Address::new([b; 20])
}

fn row(db: &Database, family: &str, key: &[u8]) -> Option<Vec<u8>> {
    db.get(family, key).unwrap()
}

// ── Config: three widths under one column family ─────────────────────────────

#[test]
fn config_values_are_bare_big_endian_at_their_own_widths() {
    let (db, _dir) = db();
    let store = MessagingStore::new(&db);

    store.set_daily_quota(7).unwrap();
    store.set_max_message_size(4096).unwrap();
    // Above u64::MAX on purpose: see the header. 0x0102...0F10.
    const WIDE: u128 = 0x0102_0304_0506_0708_090A_0B0C_0D0E_0F10;
    store.set_min_trust_stake(WIDE).unwrap();
    store.set_sponsorship_enabled(true).unwrap();
    store.set_sponsorship_balance(42).unwrap();

    assert_eq!(
        row(&db, cf::MESSAGING_CONFIG, config_keys::DAILY_QUOTA),
        Some(vec![0, 0, 0, 7]),
        "a quota is four BIG-endian bytes"
    );
    assert_eq!(
        row(&db, cf::MESSAGING_CONFIG, config_keys::MAX_MESSAGE_SIZE),
        Some(vec![0, 0, 0x10, 0])
    );
    assert_eq!(
        row(&db, cf::MESSAGING_CONFIG, config_keys::MIN_TRUST_STAKE),
        Some(vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10
        ]),
        "a stake threshold is SIXTEEN big-endian bytes, every one of them \
         significant"
    );
    assert_eq!(
        row(&db, cf::MESSAGING_CONFIG, config_keys::SPONSORSHIP_ENABLED),
        Some(vec![1]),
        "a flag is one byte"
    );
    assert_eq!(
        row(&db, cf::MESSAGING_CONFIG, config_keys::SPONSORSHIP_BALANCE),
        Some(vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 42])
    );

    // And the helpers produce those same literals, which is what makes them
    // safe for the candidate side to call.
    assert_eq!(encode_u32(7), [0, 0, 0, 7]);
    assert_eq!(
        encode_balance(WIDE),
        [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10
        ],
        "the high eight bytes carry value, so they cannot be dropped"
    );
    assert_eq!(encode_bool(true), [1]);
    assert_eq!(encode_bool(false), [0]);
}

// ── Counters ─────────────────────────────────────────────────────────────────

#[test]
fn a_sender_nonce_is_eight_bytes_at_the_address_key() {
    let (db, _dir) = db();
    let store = MessagingStore::new(&db);
    let a = addr(1);

    let n = store.increment_sender_nonce(&a).unwrap();
    assert_eq!(n, 1);
    assert_eq!(
        row(&db, cf::MESSAGING_SENDER_NONCES, a.as_bytes()),
        Some(vec![0, 0, 0, 0, 0, 0, 0, 1]),
        "eight big-endian bytes, at the bare address key"
    );
    assert_eq!(sender_nonce_key(&a), a.as_bytes(), "the key is the address");
    assert_eq!(encode_u64(1), [0, 0, 0, 0, 0, 0, 0, 1]);
}

#[test]
fn a_daily_count_is_four_bytes_under_a_composite_key() {
    let (db, _dir) = db();
    let store = MessagingStore::new(&db);
    let a = addr(2);

    store.increment_daily_message_count(&a, 19_000).unwrap();

    // The key, spelled out rather than taken from the builder under test.
    let mut expected_key = a.as_bytes().to_vec();
    expected_key.extend_from_slice(&[0, 0, 0x4A, 0x38]); // 19_000 big-endian
    assert_eq!(expected_key.len(), 24, "address(20) || day(4)");
    assert_eq!(
        row(&db, cf::MESSAGING_DAILY_COUNTS, &expected_key),
        Some(vec![0, 0, 0, 1]),
        "four big-endian bytes at address||day"
    );
    assert_eq!(daily_count_key(&a, 19_000), expected_key);
}

// ── Absence is not zero ──────────────────────────────────────────────────────

#[test]
fn a_stake_of_zero_deletes_the_row_rather_than_storing_zeroes() {
    let (db, _dir) = db();
    let store = MessagingStore::new(&db);
    let a = addr(3);

    // Again above u64::MAX, so a narrowed encoding cannot pass.
    store
        .set_stake_balance(&a, 0x0102_0304_0506_0708_090A_0B0C_0D0E_0F10)
        .unwrap();
    assert_eq!(
        row(&db, cf::MESSAGING_STAKES, a.as_bytes()),
        Some(vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10
        ]),
        "sixteen big-endian bytes, all significant"
    );
    assert_eq!(stake_key(&a), a.as_bytes());

    store.set_stake_balance(&a, 0).unwrap();
    assert_eq!(
        row(&db, cf::MESSAGING_STAKES, a.as_bytes()),
        None,
        "zero is ABSENCE here, not sixteen zero bytes"
    );
}

#[test]
fn a_spam_score_of_zero_deletes_the_row() {
    let (db, _dir) = db();
    let store = MessagingStore::new(&db);
    let a = addr(4);

    store.set_spam_score(&a, 3).unwrap();
    assert_eq!(
        row(&db, cf::MESSAGING_SPAM_SCORES, a.as_bytes()),
        Some(vec![0, 0, 0, 3])
    );
    assert_eq!(spam_score_key(&a), a.as_bytes());
    store.set_spam_score(&a, 0).unwrap();
    assert_eq!(row(&db, cf::MESSAGING_SPAM_SCORES, a.as_bytes()), None);
}

// ── Presence rows ────────────────────────────────────────────────────────────

#[test]
fn presence_rows_carry_the_bytes_their_family_expects() {
    let (db, _dir) = db();
    let store = MessagingStore::new(&db);
    let recipient = [0xAA; 32];
    let sender_hash = [0xBB; 32];
    let sender = addr(5);

    store.add_contact(&recipient, &sender_hash).unwrap();
    store.block_sender(&recipient, &sender).unwrap();

    let mut ck = recipient.to_vec();
    ck.extend_from_slice(&sender_hash);
    assert_eq!(ck.len(), 64, "recipient_hash(32) || sender_hash(32)");
    assert_eq!(
        row(&db, cf::MESSAGING_CONTACTS, &ck),
        Some(vec![1]),
        "a contact row carries the single byte 1"
    );
    assert_eq!(contact_key(&recipient, &sender_hash), ck);

    let mut bk = recipient.to_vec();
    bk.extend_from_slice(sender.as_bytes());
    assert_eq!(bk.len(), 52, "recipient_hash(32) || sender(20)");
    assert_eq!(row(&db, cf::MESSAGING_BLOCKED, &bk), Some(vec![1]));
    assert_eq!(blocked_key(&recipient, &sender), bk);

    // Different from the payment index, which is empty. A shared "presence"
    // constant across both would corrupt one of them.
    assert_eq!(PRESENT, &[1u8]);
    assert!(INDEX_PRESENT.is_empty());
}

#[test]
fn an_inbox_filter_is_one_byte_of_discriminant() {
    let (db, _dir) = db();
    let store = MessagingStore::new(&db);
    let recipient = [0xCC; 32];

    store
        .set_inbox_filter(&recipient, InboxFilter::StakedOnly)
        .unwrap();
    assert_eq!(
        row(&db, cf::MESSAGING_INBOX_FILTERS, &recipient),
        Some(vec![2]),
        "StakedOnly is the byte 2"
    );
    assert_eq!(inbox_filter_key(&recipient), &recipient);
    assert_eq!(encode_inbox_filter(InboxFilter::AcceptAll), [0u8]);
    assert_eq!(encode_inbox_filter(InboxFilter::ContactsOnly), [1u8]);
    assert_eq!(encode_inbox_filter(InboxFilter::StakedOnly), [2u8]);
}

// ── Two-row writes ───────────────────────────────────────────────────────────

#[test]
fn a_pending_payment_writes_its_primary_and_an_empty_index_row() {
    let (db, _dir) = db();
    let store = MessagingStore::new(&db);
    let id = Hash::new([0x11; 32]);
    let payment = PendingPayment {
        recipient_hash: [0x22; 32],
        amount: 900,
        expiry: 1234,
        sender: addr(6),
    };

    store.set_pending_payment(&id, &payment).unwrap();

    assert_eq!(
        row(
            &db,
            cf::MESSAGING_PENDING_PAYMENTS,
            pending_payment_key(&id)
        ),
        Some(encode_pending_payment(&payment).unwrap()),
        "the primary row is the shared encoding"
    );
    let mut ik = payment.recipient_hash.to_vec();
    ik.extend_from_slice(id.as_bytes());
    assert_eq!(ik.len(), 64, "recipient_hash(32) || message_id(32)");
    assert_eq!(
        row(&db, cf::MESSAGING_PAYMENTS_BY_RECIPIENT, &ik),
        Some(Vec::new()),
        "and the index row is EMPTY -- the key is the fact"
    );
    assert_eq!(payment_index_key(&payment.recipient_hash, &id), ik);

    // And the decode side is the same one.
    let back = decode_pending_payment(
        &row(
            &db,
            cf::MESSAGING_PENDING_PAYMENTS,
            pending_payment_key(&id),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(back, payment);

    store.delete_pending_payment(&id).unwrap();
    assert_eq!(
        row(
            &db,
            cf::MESSAGING_PENDING_PAYMENTS,
            pending_payment_key(&id)
        ),
        None
    );
    assert_eq!(
        row(&db, cf::MESSAGING_PAYMENTS_BY_RECIPIENT, &ik),
        None,
        "deleting must take the index row with it"
    );
}

#[test]
fn a_message_event_writes_the_same_bytes_under_two_keys() {
    let (db, _dir) = db();
    let store = MessagingStore::new(&db);
    let event = MessageEvent {
        sender: addr(7),
        recipient_hash: [0x33; 32],
        message_id: Hash::new([0x44; 32]),
        size: 128,
        has_payment: false,
        block_height: 99,
        timestamp: 1000,
    };

    store.store_message_event(&event, 3).unwrap();

    let mut ek = event.recipient_hash.to_vec();
    ek.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 99]); // height, big-endian
    ek.extend_from_slice(&[0, 0, 0, 3]); // tx_index, big-endian
    assert_eq!(
        ek.len(),
        44,
        "recipient_hash(32) || height(8) || tx_index(4)"
    );
    assert_eq!(event_key(&event.recipient_hash, event.block_height, 3), ek);

    let mut sk = event.sender.as_bytes().to_vec();
    sk.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 99]);
    sk.extend_from_slice(&[0, 0, 0, 3]);
    assert_eq!(sk.len(), 32, "sender(20) || height(8) || tx_index(4)");
    assert_eq!(sender_index_key(&event.sender, event.block_height, 3), sk);

    let encoded = encode_message_event(&event).unwrap();
    assert_eq!(row(&db, cf::MESSAGING_EVENTS, &ek), Some(encoded.clone()));
    assert_eq!(
        row(&db, cf::MESSAGING_SENDER_EVENTS, &sk),
        Some(encoded),
        "the index carries the WHOLE event, not a pointer to it"
    );
    assert_eq!(
        decode_message_event(&row(&db, cf::MESSAGING_EVENTS, &ek).unwrap()).unwrap(),
        event
    );
}

#[test]
fn a_public_key_row_is_the_shared_encoding_at_the_address_key() {
    let (db, _dir) = db();
    let store = MessagingStore::new(&db);
    let a = addr(8);
    let registered = RegisteredPublicKey {
        public_key: [0x55; 32],
        address: a,
        registered_at_block: 5,
        registered_at: 1000,
        updated_at_block: 0,
    };

    store.set_public_key(&a, &registered).unwrap();
    assert_eq!(public_key_key(&a), a.as_bytes(), "the key is the address");
    let stored = row(&db, cf::MESSAGING_PUBLIC_KEYS, a.as_bytes()).unwrap();
    assert_eq!(
        stored,
        encode_public_key(&registered).unwrap(),
        "the store writes what the shared encoder produces"
    );
    assert_eq!(decode_public_key(&stored).unwrap(), registered);
}
