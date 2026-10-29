//! The local-depth finality record (#350): `finalized_height` and
//! `finalized_hash` are one record, written together and checked together.
//!
//! * `set_finalized` / `stage_finalized` are the only writers, and write both
//!   keys in one batch; a batch that is never committed writes neither;
//! * `checked_finality_record` reads the pair back only when both keys decode,
//!   the height is not above the head and the hash is the canonical block at
//!   that height; neither key present is "nothing finalized"; every other
//!   state is an error, never "nothing finalized"; it writes nothing.
//!
//! All data is synthetic.

use std::collections::BTreeMap;

use sumchain_primitives::{Block, BlockHeader, BlockHeight, Hash};
use sumchain_storage::db::ALL_CFS;
use sumchain_storage::schema::{meta_keys, FinalityRecordError};
use sumchain_storage::{cf, BlockStore, Database};
use tempfile::TempDir;

fn db() -> (TempDir, Database) {
    let dir = TempDir::new().unwrap();
    let db = Database::open_default(dir.path()).unwrap();
    (dir, db)
}

fn block(parent: Hash, height: BlockHeight) -> Block {
    Block::new(
        BlockHeader::new(
            parent,
            height,
            1_000 + height,
            Hash::ZERO,
            Hash::hash(&height.to_be_bytes()),
            [0u8; 32],
        ),
        Vec::new(),
    )
}

/// Blocks 0..=head on the canonical index, with the head recorded.
fn chain(db: &Database, head: BlockHeight) -> Vec<Block> {
    let store = BlockStore::new(db);
    let mut out: Vec<Block> = Vec::new();
    for h in 0..=head {
        let parent = out.last().map_or(Hash::ZERO, Block::hash);
        let b = block(parent, h);
        store.put(&b).unwrap();
        out.push(b);
    }
    let tip = out.last().unwrap();
    store.set_latest_hash(&tip.hash()).unwrap();
    store.set_latest_height(tip.height()).unwrap();
    out
}

fn rows(db: &Database) -> BTreeMap<(String, Vec<u8>), Vec<u8>> {
    let mut out = BTreeMap::new();
    for cf_name in ALL_CFS {
        for entry in db.iter_checked_from(cf_name, None).unwrap() {
            let (k, v) = entry.unwrap();
            out.insert((cf_name.to_string(), k.into_vec()), v.into_vec());
        }
    }
    out
}

fn raw(db: &Database) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
    (
        db.get(cf::META, meta_keys::FINALIZED_HEIGHT).unwrap(),
        db.get(cf::META, meta_keys::FINALIZED_HASH).unwrap(),
    )
}

/// `checked_finality_record` refuses with `expected`, and writes nothing.
fn refused(db: &Database, expected: FinalityRecordError) {
    let before = rows(db);
    assert_eq!(
        BlockStore::new(db).checked_finality_record(),
        Err(expected.clone())
    );
    assert!(
        expected.to_string().contains("finality record"),
        "{expected}"
    );
    assert_eq!(rows(db), before, "the check wrote");
}

// ── writing ─────────────────────────────────────────────────────────────────

#[test]
fn set_finalized_writes_the_height_and_the_hash_together() {
    let (_d, db) = db();
    let blocks = chain(&db, 5);
    let store = BlockStore::new(&db);
    store.set_finalized(3, &blocks[3].hash()).unwrap();
    assert_eq!(
        raw(&db),
        (
            Some(3u64.to_be_bytes().to_vec()),
            Some(blocks[3].hash().as_bytes().to_vec())
        ),
        "the encodings are the legacy ones, unchanged"
    );
    assert_eq!(store.get_finalized_height().unwrap(), Some(3));
    assert_eq!(store.get_finalized_hash().unwrap(), Some(blocks[3].hash()));
    assert_eq!(
        store.checked_finality_record(),
        Ok(Some((3, blocks[3].hash())))
    );
}

#[test]
fn a_staged_record_is_written_whole_on_commit_and_not_at_all_without_it() {
    let (_d, db) = db();
    let blocks = chain(&db, 4);
    {
        let mut batch = db.batch();
        BlockStore::stage_finalized(&mut batch, 2, &blocks[2].hash()).unwrap();
        // Dropped without a commit: neither key.
    }
    assert_eq!(raw(&db), (None, None));

    let mut batch = db.batch();
    BlockStore::stage_finalized(&mut batch, 2, &blocks[2].hash()).unwrap();
    batch.commit().unwrap();
    assert_eq!(
        BlockStore::new(&db).checked_finality_record(),
        Ok(Some((2, blocks[2].hash())))
    );
}

// ── reading back ────────────────────────────────────────────────────────────

#[test]
fn no_record_at_all_is_nothing_finalized() {
    let (_d, db) = db();
    assert_eq!(BlockStore::new(&db).checked_finality_record(), Ok(None));
    chain(&db, 9);
    assert_eq!(BlockStore::new(&db).checked_finality_record(), Ok(None));
}

#[test]
fn a_half_present_record_is_refused() {
    let (_d, db) = db();
    let blocks = chain(&db, 5);
    db.put(cf::META, meta_keys::FINALIZED_HEIGHT, &3u64.to_be_bytes())
        .unwrap();
    refused(&db, FinalityRecordError::HeightWithoutHash { height: 3 });

    db.delete(cf::META, meta_keys::FINALIZED_HEIGHT).unwrap();
    db.put(
        cf::META,
        meta_keys::FINALIZED_HASH,
        blocks[3].hash().as_bytes(),
    )
    .unwrap();
    refused(
        &db,
        FinalityRecordError::HashWithoutHeight {
            hash: blocks[3].hash(),
        },
    );
}

#[test]
fn an_undecodable_key_is_refused() {
    let (_d, db) = db();
    let blocks = chain(&db, 5);
    BlockStore::new(&db)
        .set_finalized(3, &blocks[3].hash())
        .unwrap();

    db.put(cf::META, meta_keys::FINALIZED_HEIGHT, &[0u8; 7])
        .unwrap();
    let got = BlockStore::new(&db).checked_finality_record();
    assert!(
        matches!(got, Err(FinalityRecordError::Unreadable(_))),
        "{got:?}"
    );

    db.put(cf::META, meta_keys::FINALIZED_HEIGHT, &3u64.to_be_bytes())
        .unwrap();
    db.put(cf::META, meta_keys::FINALIZED_HASH, &[0u8; 31])
        .unwrap();
    let got = BlockStore::new(&db).checked_finality_record();
    assert!(
        matches!(got, Err(FinalityRecordError::Unreadable(_))),
        "{got:?}"
    );
}

/// The state two separate writes left behind when the second was lost: the
/// new height with the previous height's hash.
#[test]
fn a_hash_that_is_not_the_canonical_block_at_the_height_is_refused() {
    let (_d, db) = db();
    let blocks = chain(&db, 5);
    BlockStore::new(&db)
        .set_finalized(3, &blocks[2].hash())
        .unwrap();
    refused(
        &db,
        FinalityRecordError::NotCanonical {
            height: 3,
            recorded: blocks[2].hash(),
            canonical: Some(blocks[3].hash()),
        },
    );

    // No canonical block indexed at the height at all.
    db.delete(cf::BLOCK_HEIGHT, &3u64.to_be_bytes()).unwrap();
    BlockStore::new(&db)
        .set_finalized(3, &blocks[3].hash())
        .unwrap();
    refused(
        &db,
        FinalityRecordError::NotCanonical {
            height: 3,
            recorded: blocks[3].hash(),
            canonical: None,
        },
    );
}

#[test]
fn a_record_above_the_head_is_refused() {
    let (_d, db) = db();
    let blocks = chain(&db, 5);
    let store = BlockStore::new(&db);
    // The canonical index still names a block at 5; the head says 4.
    store.set_latest_height(4).unwrap();
    store.set_latest_hash(&blocks[4].hash()).unwrap();
    store.set_finalized(5, &blocks[5].hash()).unwrap();
    refused(
        &db,
        FinalityRecordError::AboveHead {
            height: 5,
            head: Some(4),
        },
    );

    let (_d2, empty) = self::db();
    BlockStore::new(&empty)
        .set_finalized(0, &blocks[0].hash())
        .unwrap();
    refused(
        &empty,
        FinalityRecordError::AboveHead {
            height: 0,
            head: None,
        },
    );
}

#[test]
fn a_record_at_the_head_or_at_genesis_reads_back() {
    let (_d, db) = db();
    let blocks = chain(&db, 5);
    let store = BlockStore::new(&db);
    for h in [0u64, 5] {
        store.set_finalized(h, &blocks[h as usize].hash()).unwrap();
        assert_eq!(
            store.checked_finality_record(),
            Ok(Some((h, blocks[h as usize].hash())))
        );
    }
}
