//! Certified Q16 exp table (plan §6). Integer/rational arithmetic only — no
//! floating point anywhere on this path.
//!
//! `EXP_TABLE[i] = round_ties_even( exp(-i/256) * 2^16 )` for `i = 0..=3016`;
//! lookups with `z >= 3017` map to 0; `EXP_TABLE[0] = 65536`.
//!
//! Reference method: range-reduce `x = i/256` to `y = x / 2^r <= 1`, bound
//! `exp(y)` by a positive rational partial sum plus a geometric tail, square the
//! interval `r` times to bound `exp(x)`, invert to bound `exp(-x)`, scale by
//! `2^16`, and certify that the resulting rational interval brackets exactly one
//! nearest integer (unique rounding). Because `exp(-i/256)` is transcendental
//! for `i > 0` it is never a half-integer, so a narrow enough interval always
//! resolves the round unambiguously.

use num_bigint::BigInt;
use num_rational::BigRational;
use num_traits::{One, ToPrimitive, Zero};

pub const Z_MAX: u32 = 3016;
pub const TABLE_LEN: usize = 3017;
pub const SCALE_BITS: u32 = 16;
pub const SCALE: u32 = 1 << SCALE_BITS; // 65536
pub const MAX_TERMS: usize = 256;

/// Per-entry certificate: the certified value, range reduction, and term count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EntryCert {
    pub value: u32,
    pub range_reduction: u32,
    pub terms: u32,
}

fn rat(n: i64, d: i64) -> BigRational {
    BigRational::new(BigInt::from(n), BigInt::from(d))
}

/// Enclose `exp(y)` for `0 <= y <= 1` in `[S_n, S_n + tail]` with `n` series
/// terms and a geometric tail bound (valid since `y/(n+2) < 1`).
fn exp_small_interval(y: &BigRational, n: usize) -> (BigRational, BigRational) {
    let mut term = BigRational::one(); // y^0 / 0!
    let mut s = BigRational::zero();
    for k in 0..=n {
        s += &term;
        term = &term * y / BigRational::from_integer(BigInt::from(k as u64 + 1));
    }
    // `term` is now y^{n+1}/(n+1)!; tail R_n <= term / (1 - y/(n+2))
    let ratio = y / BigRational::from_integer(BigInt::from(n as u64 + 2));
    let tail = &term / (BigRational::one() - ratio);
    (s.clone(), s + tail)
}

/// If the interval `[a, b]` (a <= b, both > 0) brackets exactly one nearest
/// integer, return it; else `None` (caller refines with more terms).
fn certify_round(a: &BigRational, b: &BigRational) -> Option<u32> {
    let half = rat(1, 2);
    let fa = (a + &half).floor().to_integer();
    let fb = (b + &half).floor().to_integer();
    if fa == fb {
        fa.to_u32()
    } else {
        None
    }
}

/// Certify a single entry via range reduction + interval squaring.
pub fn certified_entry(i: u32) -> EntryCert {
    if i == 0 {
        return EntryCert {
            value: SCALE,
            range_reduction: 0,
            terms: 0,
        };
    }
    let x = BigRational::new(BigInt::from(i), BigInt::from(256));
    let two = BigRational::from_integer(BigInt::from(2));
    let mut r = 0u32;
    let mut y = x.clone();
    while y > BigRational::one() {
        y /= &two;
        r += 1;
    }
    let scale = BigRational::from_integer(BigInt::from(SCALE));
    for n in 4..=MAX_TERMS {
        let (mut lo, mut hi) = exp_small_interval(&y, n);
        for _ in 0..r {
            lo = &lo * &lo;
            hi = &hi * &hi;
        }
        // exp(-x) in [1/hi, 1/lo]; scaled by 2^16
        let a = &scale / &hi;
        let b = &scale / &lo;
        if let Some(v) = certify_round(&a, &b) {
            return EntryCert {
                value: v,
                range_reduction: r,
                terms: n as u32,
            };
        }
    }
    panic!("exp entry {i} not certified within {MAX_TERMS} terms");
}

/// Generate the full certified table and per-entry certificates.
pub fn generate() -> (Vec<u32>, Vec<EntryCert>) {
    let mut table = Vec::with_capacity(TABLE_LEN);
    let mut certs = Vec::with_capacity(TABLE_LEN);
    for i in 0..TABLE_LEN as u32 {
        let c = certified_entry(i);
        table.push(c.value);
        certs.push(c);
    }
    (table, certs)
}

/// Convenience: just the values.
pub fn table() -> Vec<u32> {
    (0..TABLE_LEN as u32)
        .map(|i| certified_entry(i).value)
        .collect()
}

/// Process-cached table (the certified generation is expensive; cache it).
pub fn table_cached() -> &'static [u32] {
    use std::sync::OnceLock;
    static TABLE: OnceLock<Vec<u32>> = OnceLock::new();
    TABLE.get_or_init(table)
}

/// Frozen lookup semantics: `z <= Z_MAX` reads the table, else 0.
pub fn lookup(table: &[u32], z: u32) -> u32 {
    if z <= Z_MAX {
        table[z as usize]
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundaries() {
        assert_eq!(certified_entry(0).value, 65536);
        let t = table();
        assert_eq!(t.len(), TABLE_LEN);
        assert_eq!(t[0], 65536);
        // index 3016 is the last real entry and is small but > 0
        assert!(t[3016] >= 1);
        // lookup semantics
        assert_eq!(lookup(&t, 0), 65536);
        assert_eq!(lookup(&t, Z_MAX), t[3016]);
        assert_eq!(lookup(&t, Z_MAX + 1), 0);
        assert_eq!(lookup(&t, 10_000), 0);
    }

    #[test]
    fn monotone_non_increasing() {
        let t = table();
        for i in 1..t.len() {
            assert!(
                t[i] <= t[i - 1],
                "not monotone at {i}: {} > {}",
                t[i],
                t[i - 1]
            );
        }
    }

    #[test]
    fn deterministic_reproduction() {
        assert_eq!(table(), table());
    }

    #[test]
    fn certificate_recheck_and_mutation() {
        // an independent-style spot recheck: certified value must round the
        // scaled inverse; a mutated value fails the bracket.
        for &i in &[1u32, 256, 1000, 3016] {
            let c = certified_entry(i);
            // re-derive the interval and confirm c.value is bracketed
            let x = BigRational::new(BigInt::from(i), BigInt::from(256));
            let two = BigRational::from_integer(BigInt::from(2));
            let mut y = x;
            let mut r = 0;
            while y > BigRational::one() {
                y /= &two;
                r += 1;
            }
            let (mut lo, mut hi) = exp_small_interval(&y, 60);
            for _ in 0..r {
                lo = &lo * &lo;
                hi = &hi * &hi;
            }
            let scale = BigRational::from_integer(BigInt::from(SCALE));
            let a = &scale / &hi;
            let b = &scale / &lo;
            assert_eq!(certify_round(&a, &b), Some(c.value));
            // a wrong value is not the certified round
            assert_ne!(Some(c.value + 1), certify_round(&a, &b));
        }
    }

    #[test]
    fn table_hash_is_stable_and_mutation_sensitive() {
        let (t, _certs) = generate();
        let bytes: Vec<u8> = t.iter().flat_map(|v| v.to_le_bytes()).collect();
        let h1: [u8; 32] = blake3::hash(&bytes).into();
        let mut m = bytes.clone();
        m[0] ^= 1;
        let h2: [u8; 32] = blake3::hash(&m).into();
        assert_ne!(h1, h2);
        // regenerate -> identical hash
        let (t2, _) = generate();
        let bytes2: Vec<u8> = t2.iter().flat_map(|v| v.to_le_bytes()).collect();
        assert_eq!(h1, <[u8; 32]>::from(blake3::hash(&bytes2)));
    }
}
