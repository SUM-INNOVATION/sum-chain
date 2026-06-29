//! Executor-level coverage for the messaging sender index (issue #24): a
//! successful direct send populates the sender index; a failed send writes
//! neither the primary event nor the index.
//!
//! Integration test (not inline) so it compiles against the published crate
//! APIs, independent of the file's feature-gated legacy test module.

use std::sync::Arc;
use sumchain_genesis::ChainParams;
use sumchain_primitives::messaging::{
    ContentType, MessageFlags, MessageHeader, MessagingTxData, SendMessageData, SRC201_HEADER_SIZE,
    SRC201_MAGIC, SRC201_NONCE_SIZE, SRC201_TAG_SIZE, SRC201_VERSION,
};
use sumchain_primitives::{Address, Hash, MessagingOperation};
use sumchain_state::{MessagingExecutor, StateManager};
use sumchain_storage::{Database, MessagingStore};
use tempfile::TempDir;

fn setup() -> (Arc<Database>, TempDir, Arc<StateManager>) {
    let dir = TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let state = Arc::new(StateManager::new(db.clone(), 1));
    (db, dir, state)
}

fn valid_message(recipient_hash: [u8; 32]) -> Vec<u8> {
    let header = MessageHeader {
        magic: SRC201_MAGIC,
        version: SRC201_VERSION,
        flags: MessageFlags::encrypted(),
        content_type: ContentType::TextPlain,
        attachment_count: 0,
        recipient_hash,
        ephemeral_pubkey: [2u8; 32],
    };
    let mut v = header.to_bytes().to_vec();
    v.extend_from_slice(&[0u8; SRC201_NONCE_SIZE]); // nonce
    v.extend_from_slice(&[0u8, 0u8]); // payload_len = 0
    v.extend_from_slice(&[0u8; SRC201_TAG_SIZE]); // tag
    assert_eq!(v.len(), SRC201_HEADER_SIZE + SRC201_NONCE_SIZE + 2 + SRC201_TAG_SIZE);
    v
}

fn direct_tx(message_data: Vec<u8>, recipient_hash: [u8; 32]) -> MessagingTxData {
    MessagingTxData {
        operation: MessagingOperation::SendMessageDirect,
        data: bincode::serialize(&SendMessageData { message_data, recipient_hash }).unwrap(),
    }
}

#[test]
fn direct_send_success_writes_sender_index() {
    let (db, _dir, state) = setup();
    let executor = MessagingExecutor::new(db.clone(), ChainParams::default());
    let sender = Address::new([5u8; 20]);
    let proposer = Address::new([6u8; 20]);
    let rh = [7u8; 32];
    let tx = direct_tx(valid_message(rh), rh);

    let res = executor
        .execute(&sender, &tx, &state, &proposer, 0, 1, 1000, 0, Hash::hash(b"ok"))
        .unwrap();
    assert!(res.success, "expected success: {:?}", res.error);

    let listed = MessagingStore::new(&db).get_messages_by_sender(&sender, 100, 0).unwrap();
    assert_eq!(listed.len(), 1, "sender index must be populated on success");
    assert_eq!(listed[0].sender, sender);
}

#[test]
fn failed_send_writes_neither_primary_nor_index() {
    let (db, _dir, state) = setup();
    let executor = MessagingExecutor::new(db.clone(), ChainParams::default());
    let sender = Address::new([5u8; 20]);
    let proposer = Address::new([6u8; 20]);
    let rh = [7u8; 32];
    // Too-short message_data fails validate_message_format before any write.
    let tx = direct_tx(vec![0u8; 10], rh);

    let res = executor
        .execute(&sender, &tx, &state, &proposer, 0, 1, 1000, 0, Hash::hash(b"bad"))
        .unwrap();
    assert!(!res.success, "expected failure");

    let store = MessagingStore::new(&db);
    assert!(store.get_messages_by_sender(&sender, 100, 0).unwrap().is_empty(), "no sender index");
    assert!(
        store.get_messages_by_recipient(&rh, 0, u64::MAX, 100).unwrap().is_empty(),
        "no primary event"
    );
    assert_eq!(state.get_nonce(&sender).unwrap(), 0, "no nonce change on failure");
}
