//! Independent certified Q16 exp table (plan §6). Integer/rational only — no
//! floating point. A from-scratch cross-check of the reference table using the
//! approved **direct positive-series-then-invert** method (no range reduction,
//! no interval squaring, no shared arithmetic with the reference).
//!
//! `EXP_TABLE[i] = round_ties_even(exp(-i/256) * 2^16)`, `i = 0..=3016`;
//! `z >= 3017` maps to 0; `EXP_TABLE[0] = 65536`.

use num_bigint::BigInt;
use num_rational::BigRational;
use num_traits::{One, ToPrimitive, Zero};

pub const Z_MAX: u32 = 3016;
pub const TABLE_LEN: usize = 3017;
pub const SCALE: u32 = 1 << 16;
pub const MAX_TERMS: usize = 256;

/// Enclose `exp(x)` in `[S_n, S_n + tail]` by the direct positive series with a
/// geometric tail bound. Requires `n + 2 > x` for the bound to be valid.
fn exp_interval(x: &BigRational, n: usize) -> (BigRational, BigRational) {
    let mut term = BigRational::one();
    let mut s = BigRational::zero();
    for k in 0..=n {
        s += &term;
        term = &term * x / BigRational::from_integer(BigInt::from(k as u64 + 1));
    }
    let ratio = x / BigRational::from_integer(BigInt::from(n as u64 + 2));
    let tail = &term / (BigRational::one() - ratio);
    (s.clone(), s + tail)
}

fn round_unique(a: &BigRational, b: &BigRational) -> Option<u32> {
    let half = BigRational::new(BigInt::from(1), BigInt::from(2));
    let fa = (a + &half).floor().to_integer();
    let fb = (b + &half).floor().to_integer();
    if fa == fb {
        fa.to_u32()
    } else {
        None
    }
}

pub fn certified_entry(i: u32) -> u32 {
    if i == 0 {
        return SCALE;
    }
    let x = BigRational::new(BigInt::from(i), BigInt::from(256));
    let x_ceil = x.ceil().to_integer().to_usize().unwrap();
    let scale = BigRational::from_integer(BigInt::from(SCALE));
    // start where the geometric tail is valid (n + 2 > x)
    for n in (x_ceil + 2)..=MAX_TERMS {
        let (lo, hi) = exp_interval(&x, n);
        let a = &scale / &hi; // lower bound on exp(-x)*2^16
        let b = &scale / &lo; // upper bound
        if let Some(v) = round_unique(&a, &b) {
            return v;
        }
    }
    panic!("independent exp entry {i} not certified within {MAX_TERMS} terms");
}

pub fn table() -> Vec<u32> {
    (0..TABLE_LEN as u32).map(certified_entry).collect()
}

pub fn table_cached() -> &'static [u32] {
    use std::sync::OnceLock;
    static T: OnceLock<Vec<u32>> = OnceLock::new();
    T.get_or_init(table)
}

pub fn lookup(t: &[u32], z: u32) -> u32 {
    if z <= Z_MAX {
        t[z as usize]
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundaries_and_lookup() {
        assert_eq!(certified_entry(0), 65536);
        let t = table_cached();
        assert_eq!(t.len(), TABLE_LEN);
        assert_eq!(t[0], 65536);
        assert!(t[3016] >= 1);
        assert_eq!(lookup(t, 0), 65536);
        assert_eq!(lookup(t, Z_MAX), t[3016]);
        assert_eq!(lookup(t, Z_MAX + 1), 0);
    }

    #[test]
    fn monotone_non_increasing() {
        let t = table_cached();
        for i in 1..t.len() {
            assert!(t[i] <= t[i - 1]);
        }
    }

    #[test]
    fn deterministic() {
        assert_eq!(table(), table_cached().to_vec());
    }
}
