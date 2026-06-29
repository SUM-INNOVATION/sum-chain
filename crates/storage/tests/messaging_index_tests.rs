//! Integration tests for the SRC-201 messaging sender/payment indexes and the
//! one-time backfill (issue #24).
//!
//! These live as an integration test (rather than an inline `#[cfg(test)]`
//! module) so they compile against the storage library only, independent of
//! unrelated inline test modules in sibling stores.

use sumchain_primitives::{Address, Hash, MessageEvent, PendingPayment};
use sumchain_storage::{cf, Database, MessagingStore};
use tempfile::TempDir;

fn temp_db() -> (Database, TempDir) {
    let dir = TempDir::new().unwrap();
    let db = Database::open_default(dir.path()).unwrap();
    (db, dir)
}

fn addr(b: u8) -> Address {
    Address::new([b; 20])
}

fn event(sender: &Address, recipient_hash: [u8; 32], block: u64, tag: u8) -> MessageEvent {
    MessageEvent {
        sender: *sender,
        recipient_hash,
        message_id: Hash::hash(&[block as u8, tag]),
        size: 10,
        has_payment: false,
        block_height: block,
        timestamp: 0,
    }
}

#[test]
fn sender_index_population_and_pagination() {
    let (db, _dir) = temp_db();
    let store = MessagingStore::new(&db);
    let alice = addr(0xAA);
    let bob = addr(0xBB);

    store.store_message_event(&event(&alice, [1u8; 32], 1, 0), 0).unwrap();
    store.store_message_event(&event(&alice, [1u8; 32], 2, 0), 0).unwrap();
    store.store_message_event(&event(&alice, [1u8; 32], 3, 0), 0).unwrap();
    store.store_message_event(&event(&bob, [2u8; 32], 5, 0), 0).unwrap();

    // Only alice's, ordered ascending by block.
    let all = store.get_messages_by_sender(&alice, 100, 0).unwrap();
    assert_eq!(all.len(), 3);
    assert_eq!(all[0].block_height, 1);
    assert_eq!(all[2].block_height, 3);

    // Pagination: offset 1, limit 1 -> the middle one.
    let page = store.get_messages_by_sender(&alice, 1, 1).unwrap();
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].block_height, 2);

    // Out-of-range offset -> empty.
    assert!(store.get_messages_by_sender(&alice, 100, 9).unwrap().is_empty());
    // Other sender isolated; unknown sender empty.
    assert_eq!(store.get_messages_by_sender(&bob, 100, 0).unwrap().len(), 1);
    assert!(store.get_messages_by_sender(&addr(0xCC), 100, 0).unwrap().is_empty());
}

#[test]
fn same_block_distinct_tx_index_no_collision() {
    let (db, _dir) = temp_db();
    let store = MessagingStore::new(&db);
    let alice = addr(0xAA);
    store.store_message_event(&event(&alice, [1u8; 32], 7, 0), 0).unwrap();
    store.store_message_event(&event(&alice, [1u8; 32], 7, 1), 1).unwrap();
    assert_eq!(store.get_messages_by_sender(&alice, 100, 0).unwrap().len(), 2);
}

#[test]
fn pending_payment_recipient_index_and_delete() {
    let (db, _dir) = temp_db();
    let store = MessagingStore::new(&db);
    let rh = [9u8; 32];
    let other = [8u8; 32];
    let id1 = Hash::hash(b"p1");
    let id2 = Hash::hash(b"p2");
    let mk = |amount: u128| PendingPayment { recipient_hash: rh, amount, expiry: 1, sender: addr(1) };

    store.set_pending_payment(&id1, &mk(100)).unwrap();
    store.set_pending_payment(&id2, &mk(200)).unwrap();
    store
        .set_pending_payment(
            &Hash::hash(b"p3"),
            &PendingPayment { recipient_hash: other, amount: 5, expiry: 1, sender: addr(1) },
        )
        .unwrap();

    let mut listed = store.get_pending_payments_by_recipient(&rh).unwrap();
    assert_eq!(listed.len(), 2);
    // message_id recovered from the index key.
    listed.sort_by_key(|(_, p)| p.amount);
    assert_eq!(listed[0].0, id1);
    assert_eq!(listed[1].0, id2);
    assert_eq!(store.get_pending_payments_by_recipient(&other).unwrap().len(), 1);

    // Delete removes the index entry too.
    store.delete_pending_payment(&id1).unwrap();
    let after = store.get_pending_payments_by_recipient(&rh).unwrap();
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].0, id2);
}

#[test]
fn backfill_makes_existing_records_queryable_and_is_idempotent() {
    let (db, _dir) = temp_db();
    // Write PRIMARY rows directly (bypassing index writers) to simulate
    // pre-upgrade data.
    let alice = addr(0xAA);
    let rh = [9u8; 32];
    let id = Hash::hash(b"legacy");
    let ev = event(&alice, rh, 4, 0);
    let mut ev_key = Vec::with_capacity(44);
    ev_key.extend_from_slice(&ev.recipient_hash);
    ev_key.extend_from_slice(&ev.block_height.to_be_bytes());
    ev_key.extend_from_slice(&3u32.to_be_bytes()); // tx_index = 3
    db.put(cf::MESSAGING_EVENTS, &ev_key, &bincode::serialize(&ev).unwrap()).unwrap();
    let payment = PendingPayment { recipient_hash: rh, amount: 50, expiry: 1, sender: alice };
    db.put(cf::MESSAGING_PENDING_PAYMENTS, id.as_bytes(), &bincode::serialize(&payment).unwrap())
        .unwrap();

    let store = MessagingStore::new(&db);
    // Indexes empty before backfill.
    assert!(store.get_messages_by_sender(&alice, 100, 0).unwrap().is_empty());
    assert!(store.get_pending_payments_by_recipient(&rh).unwrap().is_empty());

    let stats = store.backfill_indexes().unwrap();
    assert!(stats.ran);
    assert_eq!(stats.sender_events, 1);
    assert_eq!(stats.pending_payments, 1);

    // Now queryable, message_id preserved.
    assert_eq!(store.get_messages_by_sender(&alice, 100, 0).unwrap().len(), 1);
    let listed = store.get_pending_payments_by_recipient(&rh).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].0, id);

    // Second run is gated (no-op) and stable.
    let again = store.backfill_indexes().unwrap();
    assert!(!again.ran);
    assert_eq!(again.sender_events, 0);
    assert_eq!(store.get_messages_by_sender(&alice, 100, 0).unwrap().len(), 1);
}

#[test]
fn backfill_fails_on_malformed_primary_and_leaves_marker_unset() {
    use sumchain_storage::messaging_store::config_keys::INDEX_BACKFILL_V1;

    let (db, _dir) = temp_db();
    // A malformed primary event row: key shorter than the 44-byte layout.
    db.put(cf::MESSAGING_EVENTS, &[0u8; 10], b"garbage").unwrap();

    let store = MessagingStore::new(&db);
    // Backfill must fail rather than skip the malformed row.
    assert!(store.backfill_indexes().is_err());
    // Completion marker must NOT be set after a failed pass.
    assert!(db.get(cf::MESSAGING_CONFIG, INDEX_BACKFILL_V1).unwrap().is_none());
    // Still ungated: a re-run re-attempts and fails again (proves no marker).
    assert!(store.backfill_indexes().is_err());
}
