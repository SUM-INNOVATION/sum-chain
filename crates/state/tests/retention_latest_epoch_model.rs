//! MODEL OF AN UNRATIFIED PROPOSAL. Nothing here is ratified, and no
//! consensus code reads it.
//!
//! #129 leaves open which assignment epochs `active_replica_count` reads (D-E)
//! and whether `since` survives a reassignment. The 2026-10-16 decision packet
//! proposes:
//!
//! * 129-B "L": count, per chunk, the distinct currently Active archives that
//!   are assigned the chunk under the file's latest assignment epoch `e_last`
//!   and attested it in `e_last`. The dependency set is the archives assigned
//!   under `e_last`, and a change of `e_last` makes the tracker Dirty.
//! * 129-D: `since` never carries over; any Dirty event forces a fresh one.
//!
//! These tests run that proposal, and the union reading "U" of the #129 text
//! and the "L′" variant for comparison, over the dormant #319 kernels
//! (`active_replica_counts_from`, `coverage_ok`, `retention_tracker_dirty`,
//! `retention_satisfied`) and the #129 reverse index. Only the epoch
//! selection, the third Dirty clause and the recompute rule are modelled here;
//! they are exactly the open choices. Assignments are explicit fixtures, not
//! the chain's assignment function, and every value is a test value.

use std::collections::{BTreeMap, BTreeSet};

use sumchain_primitives::{Address, Hash};
use sumchain_state::compute_pool::{
    retention_satisfied, retention_tracker_dirty, JobId, PoolError, RecomputeCursor,
    RetentionReverseIndex, ReverseIndexLimits, TrackerIndexRecord, TrackerKey,
};
use sumchain_state::storage_metadata::{
    active_replica_counts_from, coverage_ok, ReplicaAttestation,
};

const CHUNKS: u32 = 4;
const R_JOB: u32 = 2;
/// Test value; relations 1 and 2 bound the real one from below.
const OAB: u64 = 50;

fn addr(b: u8) -> Address {
    Address::new([b; 20])
}

const A: u8 = 0xA1;
const B: u8 = 0xB2;
const C: u8 = 0xC3;
const D: u8 = 0xD4;

/// How a tracker selects the epochs whose attestations count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reading {
    /// Proposal 129-B: assigned in `e_last`, attested in `e_last`.
    Latest,
    /// The #129 text: attested in any epoch, assigned or not now.
    Union,
    /// Assigned in `e_last`, attested in any epoch.
    LatestAssignedAnyAttest,
}

/// One file's chain-side state as the model needs it, plus each archive's
/// local disk so the GC hazard can be stated.
#[derive(Default)]
struct World {
    /// epoch height -> chunk -> archives assigned that chunk in that epoch.
    assignment: BTreeMap<u64, BTreeMap<u32, BTreeSet<Address>>>,
    /// (epoch, archive) -> attestation bitmap (LSB-first, as the chain).
    bitmaps: BTreeMap<(u64, Address), Vec<u8>>,
    active: BTreeMap<Address, bool>,
    generation: BTreeMap<Address, u64>,
    /// Chunks each archive actually holds on disk.
    disk: BTreeMap<Address, BTreeSet<u32>>,
}

impl World {
    fn e_last(&self) -> u64 {
        *self.assignment.keys().last().expect("epoch 0 exists")
    }

    fn assign(&mut self, epoch: u64, chunks: &[(u32, &[u8])]) {
        let table = chunks
            .iter()
            .map(|(c, archives)| (*c, archives.iter().copied().map(addr).collect()))
            .collect();
        self.assignment.insert(epoch, table);
        for (_, archives) in chunks {
            for a in archives.iter().copied().map(addr) {
                self.active.entry(a).or_insert(true);
                self.generation.entry(a).or_insert(0);
            }
        }
    }

    fn assigned_to(&self, epoch: u64, archive: Address) -> BTreeSet<u32> {
        self.assignment[&epoch]
            .iter()
            .filter(|(_, set)| set.contains(&archive))
            .map(|(c, _)| *c)
            .collect()
    }

    fn store(&mut self, archive: u8, chunks: &[u32]) {
        self.disk.entry(addr(archive)).or_default().extend(chunks);
    }

    fn gc(&mut self, archive: u8, chunks: &[u32]) {
        let disk = self.disk.entry(addr(archive)).or_default();
        for c in chunks {
            disk.remove(c);
        }
    }

    /// `AcceptAssignmentV2` as the chain runs it: only into the latest epoch,
    /// only for chunks assigned to the archive there. The model also requires
    /// the chunk on disk, which is what an honest archive attests.
    fn attest(&mut self, archive: u8, chunks: &[u32]) {
        let a = addr(archive);
        let epoch = self.e_last();
        let assigned = self.assigned_to(epoch, a);
        let bm = self
            .bitmaps
            .entry((epoch, a))
            .or_insert_with(|| vec![0u8; CHUNKS.div_ceil(8) as usize]);
        for &c in chunks {
            assert!(assigned.contains(&c), "chain refuses an unassigned index");
            assert!(
                self.disk[&a].contains(&c),
                "honest archive holds what it attests"
            );
            bm[(c / 8) as usize] |= 1 << (c % 8);
        }
    }

    /// A status change of the archive: it leaves (or rejoins) the active set
    /// and its status generation bumps once (proposal 129-E).
    fn set_active(&mut self, archive: u8, active: bool) {
        let a = addr(archive);
        self.active.insert(a, active);
        *self.generation.get_mut(&a).expect("known archive") += 1;
    }

    fn entries(&self, reading: Reading) -> Vec<ReplicaAttestation<'_>> {
        let e_last = self.e_last();
        let assigned_now: BTreeSet<Address> = self.assignment[&e_last]
            .values()
            .flatten()
            .copied()
            .collect();
        self.bitmaps
            .iter()
            .filter(|((epoch, archive), _)| match reading {
                Reading::Latest => *epoch == e_last,
                Reading::Union => true,
                Reading::LatestAssignedAnyAttest => assigned_now.contains(archive),
            })
            .map(|((epoch, archive), bm)| ReplicaAttestation {
                epoch: *epoch,
                archive: *archive,
                active: self.active[archive],
                bitmap: Some(bm.as_slice()),
            })
            .collect()
    }

    fn counts(&self, reading: Reading) -> Vec<u32> {
        active_replica_counts_from(CHUNKS, &self.entries(reading))
    }

    /// The dependency set the tracker is recomputed against.
    fn dependencies(&self, reading: Reading) -> Vec<Address> {
        let epochs: Vec<u64> = match reading {
            Reading::Latest | Reading::LatestAssignedAnyAttest => vec![self.e_last()],
            Reading::Union => self.assignment.keys().copied().collect(),
        };
        let set: BTreeSet<Address> = epochs
            .iter()
            .flat_map(|e| self.assignment[e].values().flatten().copied())
            .collect();
        set.into_iter().collect()
    }

    /// How many of chunk `c`'s counted archives actually hold it on disk.
    fn holders(&self, c: u32) -> u32 {
        self.disk.values().filter(|d| d.contains(&c)).count() as u32
    }
}

/// The tracker fields the model needs. `recorded_e_last` is the third Dirty
/// clause proposal 129-B adds.
#[derive(Debug, Clone, Default)]
struct Tracker {
    recorded: Vec<(Address, u64)>,
    recorded_e_last: u64,
    since: Option<u64>,
}

impl Tracker {
    fn dirty(&self, world: &World, reading: Reading) -> bool {
        let generation_or_set =
            retention_tracker_dirty(&self.recorded, &world.dependencies(reading), |a| {
                world.generation.get(a).copied()
            });
        let epoch_clause = reading != Reading::Union && self.recorded_e_last != world.e_last();
        generation_or_set || epoch_clause
    }

    /// Proposal 129-D (R-S1/R-S2): a tracker that is Dirty or has no `since`
    /// is recomputed; the recompute in block `h` sets `since` afresh to `h`
    /// when coverage holds there, else to `None`. An earlier `since` never
    /// survives.
    fn recompute(&mut self, world: &World, reading: Reading, h: u64) {
        if !self.dirty(world, reading) && self.since.is_some() {
            return;
        }
        self.recorded = world
            .dependencies(reading)
            .into_iter()
            .map(|a| (a, world.generation[&a]))
            .collect();
        self.recorded_e_last = world.e_last();
        self.since = coverage_ok(&world.counts(reading), R_JOB).then_some(h);
    }

    fn satisfied(&self, world: &World, reading: Reading, head: u64) -> bool {
        retention_satisfied(self.dirty(world, reading), self.since, head, OAB)
    }
}

/// Epoch 0 at height 100: R = 2 over archives A, B, C.
fn epoch_one() -> World {
    let mut w = World::default();
    w.assign(
        100,
        &[(0, &[A, B]), (1, &[B, C]), (2, &[A, C]), (3, &[A, B])],
    );
    w.store(A, &[0, 2, 3]);
    w.store(B, &[0, 1, 3]);
    w.store(C, &[1, 2]);
    w.attest(A, &[0, 2, 3]);
    w.attest(B, &[0, 1, 3]);
    w.attest(C, &[1, 2]);
    w
}

/// C leaves the active set; the reassignment epoch at height 200 gives C's
/// chunks to the replacement D. A and B keep their assignments.
fn reassign_c_to_d(w: &mut World) {
    w.set_active(C, false);
    w.assign(
        200,
        &[(0, &[A, B]), (1, &[B, D]), (2, &[A, D]), (3, &[A, B])],
    );
}

#[test]
fn l_full_coverage_in_first_epoch_matures_after_the_interval() {
    let w = epoch_one();
    assert_eq!(w.counts(Reading::Latest), vec![2, 2, 2, 2]);
    let mut t = Tracker::default();
    t.recompute(&w, Reading::Latest, 110);
    assert_eq!(t.since, Some(110));
    assert!(!t.satisfied(&w, Reading::Latest, 110 + OAB - 1));
    assert!(t.satisfied(&w, Reading::Latest, 110 + OAB));
}

#[test]
fn l_reassignment_drops_the_count_to_latest_epoch_attesters_and_dirties() {
    let mut w = epoch_one();
    let mut t = Tracker::default();
    t.recompute(&w, Reading::Latest, 110);
    assert!(t.satisfied(&w, Reading::Latest, 170));

    reassign_c_to_d(&mut w);
    // Nobody has attested in epoch 200 yet, although A and B still hold their
    // chunks: under L the count is 0 everywhere.
    assert_eq!(w.counts(Reading::Latest), vec![0, 0, 0, 0]);
    assert!(
        t.dirty(&w, Reading::Latest),
        "e_last and the dependency set changed"
    );
    assert!(!t.satisfied(&w, Reading::Latest, 210));

    // The epoch clause alone dirties: same archives, same generations, new
    // epoch (e.g. a reassignment that moved nothing for this file).
    let mut same_set = epoch_one();
    let mut t2 = Tracker::default();
    t2.recompute(&same_set, Reading::Latest, 110);
    let table: Vec<(u32, Vec<u8>)> = vec![
        (0, vec![A, B]),
        (1, vec![B, C]),
        (2, vec![A, C]),
        (3, vec![A, B]),
    ];
    let borrowed: Vec<(u32, &[u8])> = table.iter().map(|(c, v)| (*c, v.as_slice())).collect();
    same_set.assign(200, &borrowed);
    assert!(t2.dirty(&same_set, Reading::Latest));
}

#[test]
fn l_partial_reattest_is_not_coverage() {
    let mut w = epoch_one();
    reassign_c_to_d(&mut w);
    // A and B re-attest in epoch 200; D has not fetched its chunks.
    w.attest(A, &[0, 2, 3]);
    w.attest(B, &[0, 1, 3]);
    assert_eq!(w.counts(Reading::Latest), vec![2, 1, 1, 2]);
    let mut t = Tracker::default();
    t.recompute(&w, Reading::Latest, 205);
    assert_eq!(t.since, None);
    assert!(!t.satisfied(&w, Reading::Latest, 10_000));
}

#[test]
fn l_repair_restores_coverage_and_since_restarts() {
    let mut w = epoch_one();
    let mut t = Tracker::default();
    t.recompute(&w, Reading::Latest, 110);
    let before = t.since;

    reassign_c_to_d(&mut w);
    w.attest(A, &[0, 2, 3]);
    w.attest(B, &[0, 1, 3]);
    t.recompute(&w, Reading::Latest, 205);
    assert_eq!(t.since, None, "partial coverage leaves since unset");

    // The repair: D fetches and attests its latest-epoch chunks.
    w.store(D, &[1, 2]);
    w.attest(D, &[1, 2]);
    assert_eq!(w.counts(Reading::Latest), vec![2, 2, 2, 2]);
    // R-S2: since = None keeps the tracker selectable without a Dirty event.
    assert!(!t.dirty(&w, Reading::Latest));
    t.recompute(&w, Reading::Latest, 240);
    assert_eq!(t.since, Some(240));
    assert_ne!(t.since, before);
    assert!(!t.satisfied(&w, Reading::Latest, 240 + OAB - 1));
    assert!(t.satisfied(&w, Reading::Latest, 240 + OAB));
}

#[test]
fn l_since_never_carries_over_even_with_immediate_full_reattest() {
    let mut w = epoch_one();
    let mut t = Tracker::default();
    t.recompute(&w, Reading::Latest, 110);

    reassign_c_to_d(&mut w);
    w.attest(A, &[0, 2, 3]);
    w.attest(B, &[0, 1, 3]);
    w.store(D, &[1, 2]);
    w.attest(D, &[1, 2]);
    // Full coverage again in the very block of the reassignment.
    t.recompute(&w, Reading::Latest, 200);
    assert_eq!(t.since, Some(200), "fresh since, not 110");
    assert!(!t.satisfied(&w, Reading::Latest, 110 + OAB + 1));
}

#[test]
fn l_prime_counts_a_chunk_gc_deleted_while_assigned_away() {
    // Chunk 1: B and C in epoch 100. Epoch 200 moves C's chunk 1 to D (C stays
    // Active). C's GC deletes it. Epoch 300 moves it back to C.
    let mut w = epoch_one();
    w.assign(
        200,
        &[(0, &[A, B]), (1, &[B, D]), (2, &[A, C]), (3, &[A, B])],
    );
    w.gc(C, &[1]);
    w.assign(
        300,
        &[(0, &[A, B]), (1, &[B, C]), (2, &[A, C]), (3, &[A, B])],
    );
    // B re-attests in epoch 300; C cannot, it no longer holds chunk 1.
    w.attest(B, &[0, 1, 3]);

    let l_prime = w.counts(Reading::LatestAssignedAnyAttest)[1];
    let l = w.counts(Reading::Latest)[1];
    assert_eq!(w.holders(1), 1, "only B holds chunk 1");
    assert_eq!(l_prime, 2, "L′ still counts C's epoch-100 bit");
    assert!(l_prime > w.holders(1), "L′ over-counts: unsound");
    assert_eq!(l, 1, "L counts only the epoch-300 attester");
    assert!(l <= w.holders(1));
}

#[test]
fn union_comparison_over_the_same_sequence() {
    let mut w = epoch_one();
    let mut t = Tracker::default();
    t.recompute(&w, Reading::Union, 110);
    assert_eq!(t.since, Some(110));

    reassign_c_to_d(&mut w);
    // U keeps A's and B's epoch-100 bits; C is inactive and drops out.
    assert_eq!(w.counts(Reading::Union), vec![2, 1, 1, 2]);
    // The dependency set gained D and C's generation bumped: Dirty under U too,
    // so 129-D's "carry since over" option still resets here.
    assert!(t.dirty(&w, Reading::Union));

    w.store(D, &[1, 2]);
    w.attest(D, &[1, 2]);
    assert_eq!(
        w.counts(Reading::Union),
        vec![2, 2, 2, 2],
        "only D had to attest"
    );
    assert_eq!(
        w.counts(Reading::Latest),
        vec![0, 1, 1, 0],
        "L also needs A and B"
    );

    // U also counts an Active archive that a later epoch assigned away and
    // that then deleted the chunk (never PoR-challenged for it again).
    let mut v = epoch_one();
    v.assign(
        200,
        &[(0, &[A, B]), (1, &[B, D]), (2, &[A, C]), (3, &[A, B])],
    );
    v.gc(C, &[1]);
    v.store(D, &[1]);
    v.attest(D, &[1]);
    assert_eq!(v.holders(1), 2, "B and D hold chunk 1");
    assert_eq!(v.counts(Reading::Union)[1], 3, "U counts C's stale bit");
}

#[test]
fn l_indexes_one_epoch_union_needs_a_larger_epoch_bound() {
    let limits = ReverseIndexLimits {
        max_entries_per_job: 1_000,
        r_max: 2,
        retention_chunk_cap: 64,
        max_indexed_epochs: 1, // E_max = 1, proposal 129-F
    };
    let key = TrackerKey::from_bytes([7; 32]);
    let record = TrackerIndexRecord {
        job_id: JobId::from_bytes([1; 32]),
        file_root: Hash::new([9; 32]),
        r_job: R_JOB,
        interval_version: 1,
        chunk_count: CHUNKS,
        epochs: [100].into(),
        archives: [A, B, C].into_iter().map(addr).collect(),
    };
    let mut index = RetentionReverseIndex::new();
    index.insert_tracker(key, record, &limits).unwrap();

    // The reassignment touches the file: the tracker is enqueued once and the
    // cursor selects it.
    let pending = index.affected_trackers(&[addr(C)], &[Hash::new([9; 32])]);
    assert_eq!(pending, [key].into());
    let batch = RecomputeCursor::start().select(&pending, 1);
    assert_eq!(batch.selected, vec![key]);

    // L moves the tracker to the new epoch: still one indexed epoch.
    index
        .replace_dependencies(
            &key,
            [200].into(),
            [A, B, D].into_iter().map(addr).collect(),
            &limits,
        )
        .unwrap();
    assert_eq!(index.trackers_for_archive(&addr(C)).count(), 0);

    // U would index both epochs, which E_max = 1 refuses.
    let err = index
        .replace_dependencies(
            &key,
            [100, 200].into(),
            [A, B, C, D].into_iter().map(addr).collect(),
            &limits,
        )
        .unwrap_err();
    assert!(matches!(
        err,
        PoolError::RetentionTrackerOutOfBounds {
            what: "indexed epochs",
            ..
        }
    ));
}
