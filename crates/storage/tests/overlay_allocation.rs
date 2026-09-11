//! Does the overlay refuse an oversized write BEFORE copying it?
//!
//! The unit tests in `overlay.rs` assert that a refused write leaves the
//! overlay byte-identical. That is necessary but it is not the property the
//! limit exists for: an implementation that copies the value, measures it, then
//! throws the copy away also leaves the overlay byte-identical — and has
//! already made the allocation the limit was supposed to prevent. Both of the
//! obvious regressions (building `Op::Put(value.to_vec())` at the call site,
//! and reading the pre-image with `get` instead of `get_pinned`) pass every
//! assertion in that file.
//!
//! So the ordering needs an instrument, not an assertion. This harness installs
//! a counting global allocator, arms it around exactly one `put`, and records
//! the largest single allocation that occurred. A copy-first implementation
//! shows the payload-sized allocation; a measure-first implementation does not.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use sumchain_storage::db::{cf, Database};
use sumchain_storage::overlay::ApplicationOverlay;
use tempfile::TempDir;

thread_local! {
    /// Armed only around the call under test, so unrelated allocations by the
    /// test harness and RocksDB's own startup are not attributed to it.
    static ARMED: Cell<bool> = const { Cell::new(false) };

    /// Fail the Nth armed allocation of at least `FAIL_THRESHOLD` bytes.
    /// `0` disables. See `a_post_commit_clone_would_abort_instead_of_erroring`.
    static FAIL_THRESHOLD: Cell<usize> = const { Cell::new(0) };
    static FAIL_NTH: Cell<u32> = const { Cell::new(0) };
    static BIG_SEEN: Cell<u32> = const { Cell::new(0) };

    /// Per-thread peak. This MUST be thread-local, not a global atomic.
    ///
    /// `cargo test` runs these in parallel threads. With a shared counter, the
    /// accepted-write test's 8 MiB allocation lands in whatever peak a
    /// concurrently-armed test then reads, and the refusal tests fail at random
    /// — which is exactly what happened, intermittently, before this was
    /// thread-local. Arming is per-thread, so the measurement has to be too.
    static PEAK: Cell<usize> = const { Cell::new(0) };
}

struct Counting;

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let armed = ARMED.try_with(|a| a.get()).unwrap_or(false);
        if armed {
            // `try_with`: during thread teardown the TLS may already be gone,
            // and panicking inside the allocator would abort.
            let _ = PEAK.try_with(|p| p.set(p.get().max(layout.size())));

            let threshold = FAIL_THRESHOLD.try_with(|t| t.get()).unwrap_or(0);
            if threshold > 0 && layout.size() >= threshold {
                let n = BIG_SEEN.try_with(|c| {
                    c.set(c.get() + 1);
                    c.get()
                });
                let target = FAIL_NTH.try_with(|t| t.get()).unwrap_or(0);
                if n == Ok(target) {
                    // Refuse. A fallible caller sees `Err`; an infallible one
                    // (`Vec::clone`, `to_vec`) reaches `handle_alloc_error` and
                    // aborts the process.
                    return std::ptr::null_mut();
                }
            }
        }
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

/// Run `f` with the allocator armed, returning the largest single allocation.
fn peak_alloc_during<R>(f: impl FnOnce() -> R) -> (R, usize) {
    PEAK.with(|p| p.set(0));
    ARMED.with(|a| a.set(true));
    let out = f();
    ARMED.with(|a| a.set(false));
    (out, PEAK.with(|p| p.get()))
}

fn db() -> (Database, TempDir) {
    let dir = TempDir::new().expect("tempdir");
    let db = Database::open_default(dir.path()).expect("open db");
    (db, dir)
}

const PAYLOAD: usize = 8 * 1024 * 1024;

#[test]
fn an_oversized_value_is_measured_before_it_is_copied() {
    let (d, _g) = db();
    let mut ov = ApplicationOverlay::new(&d, 128);
    let huge = vec![0u8; PAYLOAD]; // allocated OUTSIDE the armed window

    let (result, peak) = peak_alloc_during(|| ov.put(cf::STATE, b"k", &huge));

    assert!(result.is_err(), "the write must be refused");
    assert!(
        peak < PAYLOAD,
        "the overlay allocated {peak} bytes while refusing a {PAYLOAD}-byte write — \
         it copied the value before measuring it, so the limit bounded nothing"
    );
}

#[test]
fn an_oversized_preimage_is_measured_while_pinned() {
    let (d, _g) = db();
    let big = vec![7u8; PAYLOAD];
    d.put(cf::STATE, b"k", &big).unwrap();
    drop(big);

    let mut ov = ApplicationOverlay::new(&d, 1024);
    let (result, peak) = peak_alloc_during(|| ov.put(cf::STATE, b"k", b"tiny"));

    assert!(result.is_err(), "the pre-image alone exceeds the ceiling");
    assert!(
        peak < PAYLOAD,
        "the overlay allocated {peak} bytes reading a {PAYLOAD}-byte pre-image it then \
         refused — it used a copying read instead of a pinned one. NOTE: RocksDB may \
         still materialise or decompress a block internally; this asserts only that no \
         APPLICATION-owned copy of that size was made."
    );
}

#[test]
fn an_accepted_write_does_copy_exactly_once() {
    // The mirror image: when the write IS affordable, the copy must happen —
    // otherwise the first test could pass by never storing anything at all.
    let (d, _g) = db();
    let mut ov = ApplicationOverlay::new(&d, 64 * 1024 * 1024);
    let payload = vec![3u8; PAYLOAD];

    let (result, peak) = peak_alloc_during(|| ov.put(cf::STATE, b"k", &payload));

    assert!(result.is_ok());
    assert!(
        peak >= PAYLOAD,
        "an accepted {PAYLOAD}-byte write must actually own its value; saw {peak}"
    );
    assert_eq!(ov.get(cf::STATE, b"k").unwrap().unwrap().len(), PAYLOAD);
}


// ── Post-commit allocation: fallible, or not at all ───────────────────────
//
// The commit section of `stage` must not allocate anything block-sized. It once
// did: it built ONE owned key and then `owned_key.clone()`d it into the second
// map, after `or_default()` had already mutated that map. Allocation counting
// cannot see this — correct and incorrect both make two key-sized allocations.
// What separates them is FALLIBILITY: a `try_copy` before the commit point
// returns `Err`, while a `clone` after it aborts the process.
//
// So the harness fails the SECOND large allocation and we observe how the code
// reacts. An abort cannot be caught in-process, so the scenario runs in a child
// and the parent inspects its exit status.

const SCENARIO_ENV: &str = "SUMCHAIN_OVERLAY_ALLOC_SCENARIO";
const BIG_KEY: usize = 2 * 1024 * 1024;

fn run_second_large_allocation_fails() -> bool {
    let (d, _g) = db();
    // Limit generous: this is about allocation, not about the ceiling.
    let mut ov = ApplicationOverlay::new(&d, 1 << 30);
    let key = vec![9u8; BIG_KEY];

    PEAK.with(|p| p.set(0));
    BIG_SEEN.with(|c| c.set(0));
    FAIL_THRESHOLD.with(|t| t.set(BIG_KEY));
    FAIL_NTH.with(|t| t.set(2)); // first key copy succeeds, second is refused
    ARMED.with(|a| a.set(true));

    let result = ov.put(cf::STATE, &key, b"v");

    ARMED.with(|a| a.set(false));
    FAIL_THRESHOLD.with(|t| t.set(0));

    // Reaching here at all means no abort. The write must have been reported as
    // an error rather than half-applied.
    result.is_err() && ov.is_empty() && ov.logical_bytes() == 0
}

#[test]
fn a_post_commit_clone_would_abort_instead_of_erroring() {
    if std::env::var(SCENARIO_ENV).is_ok() {
        // Child: run the scenario. Exit 0 only if the refusal was graceful.
        std::process::exit(if run_second_large_allocation_fails() {
            0
        } else {
            2
        });
    }

    let exe = std::env::current_exe().expect("test binary path");
    let status = std::process::Command::new(exe)
        .args([
            "--exact",
            "a_post_commit_clone_would_abort_instead_of_erroring",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(SCENARIO_ENV, "1")
        .status()
        .expect("spawn child");

    assert!(
        status.success(),
        "with the second large allocation refused, the overlay must return Err \
         and stay empty. Exit {status:?} means it either aborted — an infallible \
         allocation (a `clone` or `to_vec`) after the commit point — or applied \
         part of the write."
    );
}
