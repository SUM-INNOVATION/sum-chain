//! OC-2: the SRC-201 public-key registry may be SEEDED, never mutated, and a
//! node that was seeded says so for the rest of its life.
//!
//! `cf::MESSAGING_PUBLIC_KEYS` is read by consensus — `SendMessage` requires the
//! sender to hold a registered key, and both the plain and the sponsored
//! `RegisterPublicKey` refuse a duplicate — so two nodes holding different
//! registries produce different receipts for identical blocks, and receipts are
//! folded into the state root. An operator command that writes that family at
//! any height a block has been executed at is a fork with no consensus event to
//! explain it, and it is unobservable afterwards because a seeded row and a
//! registered row are the same bytes.
//!
//! [`MessagingStore::seed_registry_at_genesis`] is the narrowing: the write
//! survives only in the one shape that is an INITIAL CONDITION rather than a
//! mutation, and it carries a marker with a digest so that "were we all seeded
//! from the same set?" is a question a peer can answer.
//!
//! What these tests pin:
//!
//!  * the unsafe shapes — above genesis, into a non-empty registry, twice — are
//!    REFUSED, and refused without writing anything;
//!  * the safe shape still works;
//!  * the marker outlives the process that wrote it;
//!  * the digest is a property of the SET, so two operators who seeded the same
//!    registrations from differently ordered files agree, and two who seeded
//!    different sets do not.

use sumchain_primitives::{Address, RegisteredPublicKey};
use sumchain_storage::db::cf;
use sumchain_storage::messaging_store::{registry_seed, MessagingStore};
use sumchain_storage::schema::BlockStore;
use sumchain_storage::Database;
use tempfile::TempDir;

fn addr(n: u8) -> Address {
    let mut b = [0u8; 20];
    b[19] = n;
    Address::new(b)
}

fn key(n: u8) -> (Address, RegisteredPublicKey) {
    let a = addr(n);
    (
        a,
        RegisteredPublicKey {
            public_key: [n; 32],
            address: a,
            registered_at_block: 0,
            registered_at: 1_700_000_000,
            updated_at_block: 0,
        },
    )
}

fn temp_db() -> (Database, TempDir) {
    let dir = TempDir::new().unwrap();
    let db = Database::open_default(dir.path()).unwrap();
    (db, dir)
}

/// Every row this database holds in the registry family, so "wrote nothing" is
/// checked against the column family rather than against the API that refused.
fn registry_rows(db: &Database) -> usize {
    db.full_iter(cf::MESSAGING_PUBLIC_KEYS).unwrap().count()
}

/// The shape that forked validators: a write into a database that has already
/// executed blocks.
#[test]
fn a_seed_above_genesis_height_is_refused_and_writes_nothing() {
    let (db, _dir) = temp_db();
    BlockStore::new(&db).set_latest_height(1).unwrap();

    let err = MessagingStore::new(&db)
        .seed_registry_at_genesis(Some(1), &[key(1), key(2)])
        .expect_err("a database that has executed a block above genesis must be refused");
    let msg = err.to_string();
    assert!(
        msg.contains("height 1"),
        "the refusal must name the height it refused at, got: {msg}"
    );
    assert!(
        msg.contains("resync"),
        "and must name the only remedy there is, got: {msg}"
    );

    assert_eq!(
        registry_rows(&db),
        0,
        "a refused seed writes no registration"
    );
    assert_eq!(
        registry_seed(&db).unwrap(),
        None,
        "and records no provenance for what it did not do"
    );
}

/// One block above genesis is enough. There is no "small enough" import: the
/// first block whose receipts a seeded key changes is the fork.
#[test]
fn the_refusal_begins_at_the_first_block_above_genesis() {
    for height in [2u64, 10, 8_716_604] {
        let (db, _dir) = temp_db();
        assert!(
            MessagingStore::new(&db)
                .seed_registry_at_genesis(Some(height), &[key(1)])
                .is_err(),
            "height {height} must be refused"
        );
    }
}

/// A registry that already holds a registration is not a candidate for a seed:
/// merging an operator set into executed state is the mid-chain write by
/// another name.
#[test]
fn a_seed_into_a_non_empty_registry_is_refused() {
    let (db, _dir) = temp_db();
    let store = MessagingStore::new(&db);
    let (a, k) = key(9);
    store.set_public_key(&a, &k).unwrap();

    let err = store
        .seed_registry_at_genesis(Some(0), &[key(1)])
        .expect_err("a non-empty registry must be refused even at genesis");
    assert!(
        err.to_string().contains("already holds"),
        "the refusal must say why: {err}"
    );

    assert_eq!(
        registry_rows(&db),
        1,
        "the registration that was already there is untouched"
    );
    assert_eq!(registry_seed(&db).unwrap(), None);
}

/// The safe shape, on a database holding only genesis and on one holding no
/// block at all — a data directory a node has never started on.
#[test]
fn a_genesis_seed_writes_the_keys_and_the_marker() {
    for tip in [None, Some(0u64)] {
        let (db, _dir) = temp_db();
        let store = MessagingStore::new(&db);
        let keys = [key(3), key(1), key(2)];

        let seed = store
            .seed_registry_at_genesis(tip, &keys)
            .expect("a genesis-height seed into an empty registry is the supported shape");

        assert_eq!(seed.key_count, 3);
        assert_eq!(seed.seeded_at_height, 0);
        assert_eq!(seed.digest.len(), 64, "blake3, hex");

        for (a, k) in &keys {
            assert_eq!(
                store.get_public_key(a).unwrap().as_ref(),
                Some(k),
                "every seeded registration is readable"
            );
        }
        assert_eq!(registry_rows(&db), 3);
        assert_eq!(
            registry_seed(&db).unwrap(),
            Some(seed),
            "and the database records that an operator put them there"
        );
    }
}

/// The marker is the point. A node that seeded and restarted must still say so —
/// otherwise the fact that this node's consensus-read state did not come from
/// its own execution lives only in the terminal scrollback of whoever ran it.
#[test]
fn the_marker_survives_a_restart() {
    let dir = TempDir::new().unwrap();

    let seed = {
        let db = Database::open_default(dir.path()).unwrap();
        let s = MessagingStore::new(&db)
            .seed_registry_at_genesis(None, &[key(1), key(2)])
            .unwrap();
        // The process that performed the seed ends here, exactly as the
        // operator command's does: the node is started separately, afterwards.
        drop(db);
        s
    };

    let db = Database::open_default(dir.path()).unwrap();
    assert_eq!(
        registry_seed(&db).unwrap(),
        Some(seed.clone()),
        "a restarted node still knows its registry was seeded"
    );
    assert_eq!(
        MessagingStore::new(&db).iter_all_pubkeys().unwrap().len(),
        2
    );

    // And it still refuses a second seed, for the same reason it reports the
    // first: it must be able to say what its registry contains.
    let err = MessagingStore::new(&db)
        .seed_registry_at_genesis(None, &[key(3)])
        .expect_err("a second seed must be refused");
    assert!(
        err.to_string().contains(&seed.digest),
        "and the refusal names the seed already in place: {err}"
    );
}

/// The digest is what two validators compare, so it must be a property of the
/// SET: the same registrations in a different file order are the same seed, and
/// a different set is a different one.
#[test]
fn the_digest_identifies_the_set_and_not_the_input_order() {
    let forward = {
        let (db, _dir) = temp_db();
        MessagingStore::new(&db)
            .seed_registry_at_genesis(None, &[key(1), key(2), key(3)])
            .unwrap()
            .digest
    };
    let reversed = {
        let (db, _dir) = temp_db();
        MessagingStore::new(&db)
            .seed_registry_at_genesis(None, &[key(3), key(2), key(1)])
            .unwrap()
            .digest
    };
    assert_eq!(
        forward, reversed,
        "two operators seeding the same registrations must agree"
    );

    let different = {
        let (db, _dir) = temp_db();
        MessagingStore::new(&db)
            .seed_registry_at_genesis(None, &[key(1), key(2), key(4)])
            .unwrap()
            .digest
    };
    assert_ne!(
        forward, different,
        "and two seeding different registrations must not"
    );

    let shorter = {
        let (db, _dir) = temp_db();
        MessagingStore::new(&db)
            .seed_registry_at_genesis(None, &[key(1), key(2)])
            .unwrap()
            .digest
    };
    assert_ne!(forward, shorter, "a subset is a different set");
}

/// An empty seed would record a provenance claim for no rows, which is a lie in
/// the direction that matters: the node would announce that its registry came
/// from an operator when nothing was applied.
#[test]
fn an_empty_seed_is_refused() {
    let (db, _dir) = temp_db();
    assert!(MessagingStore::new(&db)
        .seed_registry_at_genesis(None, &[])
        .is_err());
    assert_eq!(registry_seed(&db).unwrap(), None);
}

/// A set naming the same address twice has no single answer for what the
/// registry ends up holding, and the digest would describe a set the rows do
/// not match.
#[test]
fn a_set_naming_one_address_twice_is_refused() {
    let (db, _dir) = temp_db();
    let (a, k) = key(1);
    let mut other = k.clone();
    other.public_key = [77u8; 32];
    assert!(MessagingStore::new(&db)
        .seed_registry_at_genesis(None, &[(a, k), (a, other)])
        .is_err());
    assert_eq!(registry_rows(&db), 0);
    assert_eq!(registry_seed(&db).unwrap(), None);
}

/// A marker row this binary cannot read is an ERROR, not an absent seed.
/// `None` is a positive claim — "this registry came from my own execution" — and
/// a node that cannot read the row is in no position to make it.
#[test]
fn an_unreadable_marker_is_not_read_as_no_seed() {
    let (db, _dir) = temp_db();
    db.put(
        cf::META,
        sumchain_storage::messaging_store::REGISTRY_SEED_META_KEY,
        b"not json",
    )
    .unwrap();
    let err = registry_seed(&db).expect_err("an unreadable marker must not read as None");
    assert!(
        err.to_string().contains("unreadable"),
        "and must say so: {err}"
    );
}
