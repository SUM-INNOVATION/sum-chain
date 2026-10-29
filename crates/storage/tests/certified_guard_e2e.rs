//! The certified path end to end, inside storage and dormant (#270):
//! blocks committed through the #292 seam with the #337 v1 META layout,
//! recovered by `recover_v1`, and then the #341 crossing guard over the real
//! committed state:
//!
//! * the guard reads exactly the pointer the seam committed and `recover_v1`
//!   accepts;
//! * a reorg forking below the certified head, or a rollback below it, is
//!   refused; extending the certified head, or rolling back to it, is not;
//! * losing the pointer while certificate rows remain is refused by the guard,
//!   as `recover_v1` refuses it;
//! * a database that never certified anything is "nothing certified";
//! * the start-up audit this binary runs (`audit_at_start`, which has no
//!   certificate verifier) refuses a certified database it cannot re-verify,
//!   and passes one that never certified anything.
//!
//! The certificate verifier is the same structural stand-in
//! `tests/certified_meta_v1.rs` uses (magic, length, height and block id; no
//! signatures), because storage must not depend on the finality crate. All data
//! is synthetic.

use std::path::Path;

use sumchain_primitives::{Block, BlockHeader, BlockHeight, Hash};
use sumchain_storage::candidate::{
    BlockJournals, CandidateExecution, ExecutedCandidate, ExecutionSubject, JournalRecord,
};
use sumchain_storage::certified::{
    CertificateRefusal, CertificateVerifier, CertifiedStore, FinalizedPointer, Recovery,
};
use sumchain_storage::certified_guard::{
    audit_at_start, certified_block, refuse_reorg_crossing, refuse_rollback_crossing,
    CertifiedBlock, CrossingRefusal,
};
use sumchain_storage::certified_meta::{recover_v1, MetaLayoutV1, FINALIZED_POINTER_KEY};
use sumchain_storage::db::{cf, Database};
use tempfile::TempDir;

const TEST_LIMIT: u64 = 1 << 20;

/// `FCRTv1` ‖ NUL, spelled as bytes (the magic's only literal home is the
/// finality crate).
const CERT_MAGIC: [u8; 7] = [0x46, 0x43, 0x52, 0x54, 0x76, 0x31, 0x00];
const HEADER: usize = 119;
const ENTRY: usize = 66;

fn v1_cert(height: BlockHeight, hash: &Hash, k: u16) -> Vec<u8> {
    let mut c = Vec::with_capacity(HEADER + ENTRY * usize::from(k));
    c.extend_from_slice(&CERT_MAGIC);
    c.extend_from_slice(&1u16.to_le_bytes());
    c.extend_from_slice(&[0xc0; 32]);
    c.extend_from_slice(&height.to_le_bytes());
    c.extend_from_slice(hash.as_bytes());
    c.extend_from_slice(&0u32.to_le_bytes());
    c.extend_from_slice(&[0x5a; 32]);
    c.extend_from_slice(&k.to_le_bytes());
    for i in 0..k {
        c.extend_from_slice(&i.to_le_bytes());
        c.extend_from_slice(&[0u8; 64]);
    }
    c
}

struct V1Shape;

impl CertificateVerifier for V1Shape {
    fn verify(
        &self,
        height: BlockHeight,
        block_hash: &Hash,
        c: &[u8],
    ) -> Result<(), CertificateRefusal> {
        let refuse = |why: &str| Err(CertificateRefusal(why.into()));
        if c.len() < HEADER || c[..7] != CERT_MAGIC || c[7..9] != 1u16.to_le_bytes() {
            return refuse("not a v1 certificate header");
        }
        let k = u16::from_le_bytes([c[117], c[118]]);
        if k == 0 || c.len() != HEADER + ENTRY * usize::from(k) {
            return refuse("length is not 119 + 66k");
        }
        if u64::from_le_bytes(c[41..49].try_into().unwrap()) != height {
            return refuse("certificate names another height");
        }
        if &c[49..81] != block_hash.as_bytes() {
            return refuse("certificate names another block");
        }
        Ok(())
    }
}

fn open(dir: &Path) -> Database {
    Database::open_default(dir).expect("open")
}

fn root_for(height: BlockHeight, tag: u64) -> Hash {
    Hash::hash(&[height.to_be_bytes(), tag.to_be_bytes()].concat())
}

fn child(parent: &Block, tag: u64) -> Block {
    let height = parent.height() + 1;
    Block::new(
        BlockHeader::new(
            parent.hash(),
            height,
            1_000 + height * 10 + tag,
            Hash::ZERO,
            root_for(height, tag),
            [7u8; 32],
        ),
        Vec::new(),
    )
}

fn executed<'d>(db: &'d Database, block: &Block) -> ExecutedCandidate<'d> {
    let mut cand = CandidateExecution::new(db, TEST_LIMIT);
    cand.view()
        .put(
            cf::STATE,
            format!("test-acct:{}", block.height()).as_bytes(),
            &block.hash().as_bytes()[..],
        )
        .unwrap();
    cand.finish_execution(
        ExecutionSubject::of(block).unwrap(),
        block.header.state_root,
        Vec::new(),
        BlockJournals {
            account: JournalRecord::NothingToUndo,
            contract: JournalRecord::NothingToUndo,
            compute_pool: JournalRecord::NothingToUndo,
            beacon: JournalRecord::NothingToUndo,
        },
    )
}

fn genesis(db: &Database) -> Block {
    let g = Block::new(
        BlockHeader::new(Hash::ZERO, 0, 1_000, Hash::ZERO, root_for(0, 0), [7u8; 32]),
        Vec::new(),
    );
    executed(db, &g)
        .accept_produced(&g)
        .unwrap()
        .publish()
        .unwrap();
    g
}

/// Genesis on the ordinary path, then `n` blocks committed through the seam
/// with the v1 META layout (pointer + certificate in the block's own batch).
fn certified_chain(db: &Database, n: u64) -> Vec<Block> {
    let mut chain = vec![genesis(db)];
    for _ in 0..n {
        let b = child(chain.last().unwrap(), 0);
        let accepted = executed(db, &b).accept_imported(&b).unwrap();
        CertifiedStore::new(db, MetaLayoutV1, V1Shape)
            .commit(accepted, &v1_cert(b.height(), &b.hash(), 3))
            .unwrap();
        chain.push(b);
    }
    chain
}

fn as_pair(b: &Block) -> (BlockHeight, Hash) {
    (b.height(), b.hash())
}

#[test]
fn the_guard_reads_the_pointer_the_seam_committed_and_recover_v1_accepts() {
    let dir = TempDir::new().unwrap();
    let db = open(dir.path());
    let chain = certified_chain(&db, 4);
    let head = chain.last().unwrap();

    let recovered = recover_v1(&db, &V1Shape).unwrap();
    assert_eq!(
        recovered,
        Recovery::Finalized(FinalizedPointer {
            height: head.height(),
            hash: head.hash(),
        })
    );
    assert_eq!(
        certified_block(&db).unwrap(),
        Some(CertifiedBlock {
            height: head.height(),
            hash: head.hash(),
        })
    );
}

#[test]
fn over_committed_state_crossing_switches_are_refused_and_extensions_are_not() {
    let dir = TempDir::new().unwrap();
    let db = open(dir.path());
    let chain = certified_chain(&db, 4);
    let certified = certified_block(&db).unwrap();
    let c = certified.as_ref().unwrap();
    assert_eq!(c.height, 4);

    // A competing branch forking at block 2: it would unwind certified 3 and 4.
    let fork = &chain[2];
    let unwound = chain[3..].iter().map(as_pair);
    assert!(matches!(
        refuse_reorg_crossing(certified.as_ref(), fork.height(), &fork.hash(), unwound),
        Err(CrossingRefusal::ForkBelowCertified { fork_height: 2, .. })
    ));

    // A competing block at height 4 (same parent, another tag) cannot replace it.
    let rival = child(&chain[3], 9);
    assert_ne!(rival.hash(), chain[4].hash());
    assert!(matches!(
        refuse_reorg_crossing(certified.as_ref(), 4, &rival.hash(), std::iter::empty()),
        Err(CrossingRefusal::ForkReplacesCertified { .. })
    ));

    // Extending the certified head is a switch that crosses nothing.
    let head = chain.last().unwrap();
    assert!(refuse_reorg_crossing(
        certified.as_ref(),
        head.height(),
        &head.hash(),
        std::iter::empty()
    )
    .is_ok());

    // Rolling back below the certified head is refused; to it, allowed.
    assert!(matches!(
        refuse_rollback_crossing(certified.as_ref(), 3, &chain[3].hash()),
        Err(CrossingRefusal::RollbackBelowCertified {
            target_height: 3,
            ..
        })
    ));
    assert!(refuse_rollback_crossing(certified.as_ref(), 4, &head.hash()).is_ok());
}

#[test]
fn a_lost_pointer_with_certificate_rows_is_refused_by_the_guard_as_by_recover_v1() {
    let dir = TempDir::new().unwrap();
    let db = open(dir.path());
    certified_chain(&db, 3);
    db.delete(cf::META, FINALIZED_POINTER_KEY).unwrap();

    assert!(matches!(
        certified_block(&db),
        Err(CrossingRefusal::CertificatesWithoutPointer { height: Some(_) })
    ));
    assert!(
        recover_v1(&db, &V1Shape).is_err(),
        "recover_v1 refuses the same state"
    );
}

#[test]
fn a_database_that_never_certified_anything_has_nothing_to_protect() {
    let dir = TempDir::new().unwrap();
    let db = open(dir.path());
    let g = genesis(&db);
    let b1 = child(&g, 0);
    executed(&db, &b1)
        .accept_imported(&b1)
        .unwrap()
        .publish()
        .unwrap();

    assert_eq!(recover_v1(&db, &V1Shape).unwrap(), Recovery::NeverCertified);
    assert_eq!(certified_block(&db).unwrap(), None);
    assert!(refuse_rollback_crossing(None, 0, &g.hash()).is_ok());
    assert_eq!(
        audit_at_start(&db).unwrap(),
        None,
        "this binary's start-up audit passes it"
    );
}

/// The committed certified state that `recover_v1` accepts with a verifier is
/// refused by the start-up audit this binary runs, which has none: it does not
/// trust a certificate it cannot re-verify. Nothing is written.
#[test]
fn the_start_up_audit_refuses_a_certified_database_it_cannot_verify() {
    let dir = TempDir::new().unwrap();
    let db = open(dir.path());
    certified_chain(&db, 3);
    assert!(recover_v1(&db, &V1Shape).is_ok(), "the records are sound");
    let pointer = db.get(cf::META, FINALIZED_POINTER_KEY).unwrap();

    let err = audit_at_start(&db).unwrap_err().to_string();
    assert!(
        err.contains("no finality-certificate verifier") && err.contains("height 3"),
        "{err}"
    );
    assert_eq!(db.get(cf::META, FINALIZED_POINTER_KEY).unwrap(), pointer);
}
