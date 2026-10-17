//! MODEL OF AN UNRATIFIED PROPOSAL. Nothing here is ratified, no consensus
//! code reads it, and no value of `G` is chosen anywhere in this file.
//!
//! Proposal P5 (`docs/proposals/129-latest-epoch/README.md`): once PoR
//! targeting is on, an archive that a reassignment newly assigns a chunk must
//! not be challengeable for that chunk before it could have fetched it. The
//! proposed rule is a chain-side readiness window:
//!
//! * Let `e` be the file's latest assignment epoch at height `h`. Only
//!   archives assigned the chunk under `e` are targets.
//! * An archive is *ready* for the chunk at the start of `e` if `e` is the
//!   file's first epoch, or if it was assigned the chunk under the previous
//!   epoch and was already challengeable for it at that epoch's last height.
//!   A ready archive is challengeable for the whole of `e`, as today.
//! * Otherwise it becomes challengeable at the first height `h` at which it
//!   has attested the chunk in `e`, or at which `h >= e + G`, whichever comes
//!   first.
//!
//! `G = 0` is today's behaviour: every archive assigned under the latest
//! epoch is a target at once. The tests run the rule over several `G` values
//! purely as test parameters. The rule is evaluated over the canonical event
//! log, so a reorg is modelled by replacing a suffix of that log.

use std::collections::{BTreeMap, BTreeSet};

type Archive = u8;
type Chunk = u32;
type Height = u64;

const A: Archive = 0xA1;
const B: Archive = 0xB2;
const C: Archive = 0xC3;
const D: Archive = 0xD4;

/// Test parameters only; none of these is a proposed value.
const G_VALUES: [u64; 4] = [1, 5, 20, 64];

#[derive(Debug, Clone, PartialEq, Eq)]
enum Event {
    /// A new assignment epoch starts at this height (the initial assignment,
    /// or a reassignment): chunk -> archives assigned under it.
    Epoch(BTreeMap<Chunk, BTreeSet<Archive>>),
    /// `AcceptAssignmentV2` into the latest epoch for these chunks.
    Attest(Archive, Vec<Chunk>),
}

/// The canonical chain as the model needs it: events by height, in order.
#[derive(Debug, Clone, Default)]
struct Chain {
    log: Vec<(Height, Event)>,
}

fn table(rows: &[(Chunk, &[Archive])]) -> BTreeMap<Chunk, BTreeSet<Archive>> {
    rows.iter()
        .map(|(c, a)| (*c, a.iter().copied().collect()))
        .collect()
}

impl Chain {
    fn epoch(&mut self, h: Height, rows: &[(Chunk, &[Archive])]) {
        self.push(h, Event::Epoch(table(rows)));
    }

    fn attest(&mut self, h: Height, a: Archive, chunks: &[Chunk]) {
        self.push(h, Event::Attest(a, chunks.to_vec()));
    }

    fn push(&mut self, h: Height, e: Event) {
        if let Some((last, _)) = self.log.last() {
            assert!(h >= *last, "events are appended in height order");
        }
        self.log.push((h, e));
    }

    /// A reorg: every event above `fork` is replaced by the other branch.
    fn reorg(&mut self, fork: Height, other: &Chain) {
        self.log.retain(|(h, _)| *h <= fork);
        self.log
            .extend(other.log.iter().filter(|(h, _)| *h > fork).cloned());
    }

    /// Epoch start heights at or below `h`, with their assignment tables.
    fn epochs_upto(&self, h: Height) -> Vec<(Height, &BTreeMap<Chunk, BTreeSet<Archive>>)> {
        self.log
            .iter()
            .filter(|(eh, _)| *eh <= h)
            .filter_map(|(eh, e)| match e {
                Event::Epoch(t) => Some((*eh, t)),
                Event::Attest(..) => None,
            })
            .collect()
    }

    /// First height in `[from, h]` at which `a` attested `c` (attestations
    /// land in the epoch that is latest when they execute).
    fn attested_in(&self, a: Archive, c: Chunk, from: Height, h: Height) -> Option<Height> {
        self.log.iter().find_map(|(eh, e)| match e {
            Event::Attest(who, cs) if *who == a && *eh >= from && *eh <= h && cs.contains(&c) => {
                Some(*eh)
            }
            _ => None,
        })
    }

    /// The proposed P5 rule.
    fn challengeable(&self, a: Archive, c: Chunk, h: Height, g: u64) -> bool {
        let epochs = self.epochs_upto(h);
        let Some(&(e, t)) = epochs.last() else {
            return false;
        };
        if !t.get(&c).is_some_and(|s| s.contains(&a)) {
            return false;
        }
        if self.ready_at_start(a, c, &epochs, g) {
            return true;
        }
        self.attested_in(a, c, e, h).is_some() || h >= e.saturating_add(g)
    }

    fn ready_at_start(
        &self,
        a: Archive,
        c: Chunk,
        epochs: &[(Height, &BTreeMap<Chunk, BTreeSet<Archive>>)],
        g: u64,
    ) -> bool {
        match epochs {
            [] => false,
            [_only] => true, // the file's first epoch: today's behaviour
            [.., (_, prev_t), (e, _)] => {
                prev_t.get(&c).is_some_and(|s| s.contains(&a))
                    && *e > 0
                    && self.challengeable(a, c, *e - 1, g)
            }
        }
    }

    /// Every (archive, chunk) pair challengeable at each height of `range`.
    fn trace(
        &self,
        range: std::ops::RangeInclusive<Height>,
        g: u64,
    ) -> Vec<BTreeSet<(Archive, Chunk)>> {
        range
            .map(|h| {
                let mut out = BTreeSet::new();
                for a in [A, B, C, D] {
                    for c in 0..4 {
                        if self.challengeable(a, c, h, g) {
                            out.insert((a, c));
                        }
                    }
                }
                out
            })
            .collect()
    }
}

/// Initial epoch at 10: A and B hold chunk 0. Reassignment at 100 moves
/// chunk 0 to B (continuing) and C (newly assigned).
fn base() -> Chain {
    let mut ch = Chain::default();
    ch.epoch(10, &[(0, &[A, B])]);
    ch.epoch(100, &[(0, &[B, C])]);
    ch
}

#[test]
fn p5_attesting_before_g_is_challengeable_from_the_attestation() {
    for g in G_VALUES.into_iter().filter(|g| *g >= 2) {
        let mut ch = base();
        let at = 100 + g / 2;
        ch.attest(at, C, &[0]);
        assert!(
            !ch.challengeable(C, 0, at - 1, g),
            "G={g}: not before attesting"
        );
        assert!(
            ch.challengeable(C, 0, at, g),
            "G={g}: from the attestation height"
        );
        assert!(
            ch.challengeable(C, 0, 100 + g - 1, g),
            "G={g}: and through the window"
        );
    }
}

#[test]
fn p5_an_unattested_archive_becomes_challengeable_exactly_at_e_plus_g() {
    for g in G_VALUES {
        let ch = base();
        assert!(
            !ch.challengeable(C, 0, 100 + g - 1, g),
            "G={g}: not at e + G - 1"
        );
        assert!(ch.challengeable(C, 0, 100 + g, g), "G={g}: at e + G");
        assert!(
            ch.challengeable(C, 0, 100 + g + 1_000, g),
            "G={g}: and after"
        );
    }
}

#[test]
fn p5_g_zero_is_todays_behaviour() {
    let ch = base();
    // Every archive assigned under the latest epoch is a target at once ...
    assert!(ch.challengeable(C, 0, 100, 0));
    assert!(ch.challengeable(B, 0, 100, 0));
    // ... and an archive moved off the chunk is not.
    assert!(!ch.challengeable(A, 0, 100, 0));
    // The initial epoch's assignees are targets from its first height.
    assert!(ch.challengeable(A, 0, 10, 0) && ch.challengeable(B, 0, 10, 0));
}

#[test]
fn p5_an_archive_assigned_before_and_after_is_unaffected() {
    for g in G_VALUES {
        let ch = base();
        assert!(
            ch.challengeable(B, 0, 99, g),
            "G={g}: B before the reassignment"
        );
        assert!(
            ch.challengeable(B, 0, 100, g),
            "G={g}: B at the reassignment, no gap"
        );
        assert!(
            !ch.challengeable(A, 0, 100, g),
            "G={g}: A is no longer a target"
        );
    }
}

#[test]
fn p5_a_reorg_across_the_boundary_recomputes_from_the_canonical_log() {
    for g in G_VALUES {
        // Branch 1 (above): reassignment at 100 newly assigns C.
        let mut ch = base();
        assert!(!ch.challengeable(C, 0, 100, g));

        // Branch 2 forks at 99 with no reassignment: C is never a target,
        // A stays one.
        let mut no_reassign = Chain::default();
        no_reassign.epoch(10, &[(0, &[A, B])]);
        ch.reorg(99, &no_reassign);
        assert!(
            !ch.challengeable(C, 0, 100 + g, g),
            "G={g}: C not a target after the reorg"
        );
        assert!(
            ch.challengeable(A, 0, 100 + g, g),
            "G={g}: A still a target"
        );

        // Branch 3 reassigns at 105 instead: C's window starts at 105.
        let mut later = Chain::default();
        later.epoch(10, &[(0, &[A, B])]);
        later.epoch(105, &[(0, &[B, C])]);
        ch.reorg(99, &later);
        assert!(
            !ch.challengeable(C, 0, 105 + g - 1, g),
            "G={g}: window anchored at 105"
        );
        assert!(ch.challengeable(C, 0, 105 + g, g));
    }
}

#[test]
fn p5_two_reassignments_in_a_row_restart_the_window() {
    for g in G_VALUES.into_iter().filter(|g| *g > 5) {
        // C is newly assigned at 100 and, before its window closes, a second
        // reassignment at 105 keeps it assigned. It was not challengeable at
        // 104, so it is not ready at 105's start: the window restarts.
        let mut ch = base();
        ch.epoch(105, &[(0, &[C, D])]);
        assert!(
            !ch.challengeable(C, 0, 100 + g, g),
            "G={g}: the old deadline no longer applies"
        );
        assert!(!ch.challengeable(C, 0, 105 + g - 1, g));
        assert!(
            ch.challengeable(C, 0, 105 + g, g),
            "G={g}: the new deadline"
        );
        // D, newly assigned at 105, has the same window.
        assert!(!ch.challengeable(D, 0, 105 + g - 1, g));
        assert!(ch.challengeable(D, 0, 105 + g, g));
        // B was moved off the chunk at 105.
        assert!(!ch.challengeable(B, 0, 105, g));
    }
    // Once C was challengeable at the end of epoch 100, it stays challengeable
    // through the next reassignment (G = 1: ready at 101).
    let mut ch = base();
    ch.epoch(105, &[(0, &[C, D])]);
    assert!(ch.challengeable(C, 0, 105, 1));
    assert!(!ch.challengeable(D, 0, 105, 1));
}

#[test]
fn p5_results_are_deterministic() {
    for g in G_VALUES.into_iter().chain([0]) {
        let build = || {
            let mut ch = base();
            ch.attest(102, C, &[0]);
            ch.epoch(140, &[(0, &[C, D]), (1, &[A])]);
            ch.attest(141, D, &[0]);
            ch
        };
        let first = build().trace(0..=260, g);
        let second = build().trace(0..=260, g);
        assert_eq!(first, second, "G={g}: identical results on every run");
    }
}
