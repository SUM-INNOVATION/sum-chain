//! `FinalityCertificateV1::decode` checks the total length against
//! `119 + 66·k` before it allocates anything for the entries. A counting
//! global allocator (this test binary only) records the largest single
//! allocation the decoding thread requests while decoding.
//!
//! One test function, so no other test runs in this binary at the same time.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};

use sumchain_finality_foundations::certificate::{
    certificate_len, CertificateDecodeError, FinalityCertificateV1, CERT_HEADER_LEN, CERT_MAGIC,
    MAX_CERT_LEN, MAX_VALIDATORS,
};

struct Counting;

static LARGEST: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    static TRACKING: Cell<bool> = const { Cell::new(false) };
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if TRACKING.with(Cell::get) {
            LARGEST.fetch_max(layout.size(), Ordering::SeqCst);
        }
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// The largest single allocation `f` requested on this thread.
fn largest_allocation<T>(f: impl FnOnce() -> T) -> (T, usize) {
    LARGEST.store(0, Ordering::SeqCst);
    TRACKING.with(|t| t.set(true));
    let out = f();
    TRACKING.with(|t| t.set(false));
    (out, LARGEST.load(Ordering::SeqCst))
}

fn header(k: u16) -> Vec<u8> {
    let mut b = Vec::with_capacity(CERT_HEADER_LEN);
    b.extend_from_slice(&CERT_MAGIC);
    b.extend_from_slice(&1u16.to_le_bytes());
    b.extend_from_slice(&[0xc0; 32]);
    b.extend_from_slice(&7u64.to_le_bytes());
    b.extend_from_slice(&[0xb1; 32]);
    b.extend_from_slice(&0u32.to_le_bytes());
    b.extend_from_slice(&[0x5a; 32]);
    b.extend_from_slice(&k.to_le_bytes());
    assert_eq!(b.len(), CERT_HEADER_LEN);
    b
}

#[test]
fn an_over_declared_k_is_refused_before_any_entry_allocation() {
    // Header alone, declaring the maximum k.
    let short = header(MAX_VALIDATORS);
    let (result, largest) = largest_allocation(|| FinalityCertificateV1::decode(&short));
    assert_eq!(
        result,
        Err(CertificateDecodeError::Length {
            k: MAX_VALIDATORS,
            expected: MAX_CERT_LEN,
            actual: CERT_HEADER_LEN
        })
    );
    assert_eq!(
        largest, 0,
        "nothing allocated before the length check refused"
    );

    // Header plus one entry, declaring the maximum k.
    let mut one = header(MAX_VALIDATORS);
    one.extend_from_slice(&0u16.to_le_bytes());
    one.extend_from_slice(&[0u8; 64]);
    let (result, largest) = largest_allocation(|| FinalityCertificateV1::decode(&one));
    assert!(matches!(result, Err(CertificateDecodeError::Length { .. })));
    assert_eq!(largest, 0);

    // A short buffer must never cost an allocation of the declared size.
    let declared = certificate_len(MAX_VALIDATORS);
    assert!(declared > 4_000_000);

    // Positive control: a valid full-size certificate does allocate its
    // entries (so the counter works), and only once the length matched.
    let mut full = header(MAX_VALIDATORS);
    for i in 0..MAX_VALIDATORS {
        full.extend_from_slice(&i.to_le_bytes());
        full.extend_from_slice(&[0u8; 64]);
    }
    assert_eq!(full.len(), MAX_CERT_LEN);
    let (result, largest) = largest_allocation(|| FinalityCertificateV1::decode(&full));
    assert_eq!(result.expect("structurally valid").signer_count(), 65_535);
    assert!(
        largest >= usize::from(MAX_VALIDATORS) * 66,
        "the entry vector was allocated ({largest} bytes)"
    );
}
