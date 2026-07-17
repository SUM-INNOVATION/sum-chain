//! Frozen fixed-point integer arithmetic (plan §7). No floating point anywhere.
//!
//! Tensors are `i16` at scale `S = 2^8` (Q8); accumulators are checked `i64`
//! (widened to `i128` inside `rhaz` so the doubling cannot overflow).

/// Round-half-away-from-zero division by a positive divisor.
pub fn rhaz(n: i64, d: i64) -> i64 {
    debug_assert!(d > 0);
    let n = n as i128;
    let d = d as i128;
    let bias = if n >= 0 { d } else { -d };
    ((2 * n + bias) / (2 * d)) as i64
}

/// `requantize = RHAZ(·, 256)` (drop one Q8 scale factor).
pub fn requantize(v: i64) -> i64 {
    rhaz(v, 256)
}

/// Newton floor integer square root for `n >= 0`.
pub fn isqrt(n: i64) -> i64 {
    if n < 2 {
        return n.max(0);
    }
    let mut x0 = n / 2;
    let mut x1 = (x0 + n / x0) / 2;
    while x1 < x0 {
        x0 = x1;
        x1 = (x0 + n / x0) / 2;
    }
    x0
}

/// Saturating conversion of an `i64` accumulator to `i16`.
pub fn saturate(v: i64) -> i16 {
    if v > i16::MAX as i64 {
        i16::MAX
    } else if v < i16::MIN as i64 {
        i16::MIN
    } else {
        v as i16
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rhaz_positive_and_negative_ties_round_away() {
        assert_eq!(rhaz(1, 2), 1); // 0.5 -> 1
        assert_eq!(rhaz(3, 2), 2); // 1.5 -> 2
        assert_eq!(rhaz(5, 2), 3); // 2.5 -> 3
        assert_eq!(rhaz(2, 4), 1); // 0.5 -> 1
        assert_eq!(rhaz(-1, 2), -1); // -0.5 -> -1
        assert_eq!(rhaz(-3, 2), -2); // -1.5 -> -2
        assert_eq!(rhaz(-5, 2), -3);
        // non-tie rounding
        assert_eq!(rhaz(7, 3), 2); // 2.333 -> 2
        assert_eq!(rhaz(8, 3), 3); // 2.667 -> 3
        assert_eq!(rhaz(-7, 3), -2);
        assert_eq!(rhaz(-8, 3), -3);
        assert_eq!(rhaz(0, 5), 0);
    }

    #[test]
    fn requantize_by_256() {
        assert_eq!(requantize(256), 1);
        assert_eq!(requantize(128), 1); // 0.5 -> 1
        assert_eq!(requantize(384), 2); // 1.5 -> 2
        assert_eq!(requantize(-128), -1);
        assert_eq!(requantize(-384), -2);
    }

    #[test]
    fn isqrt_floor() {
        for (n, r) in [
            (0, 0),
            (1, 1),
            (2, 1),
            (3, 1),
            (4, 2),
            (8, 2),
            (15, 3),
            (16, 4),
            (17, 4),
        ] {
            assert_eq!(isqrt(n), r, "isqrt({n})");
        }
        assert_eq!(isqrt(1_000_000_000_000), 1_000_000);
        // isqrt(k^2) == k and isqrt(k^2 - 1) == k-1 for a range
        for k in 1..2000i64 {
            assert_eq!(isqrt(k * k), k);
            assert_eq!(isqrt(k * k - 1), k - 1);
        }
    }

    #[test]
    fn saturate_boundaries() {
        assert_eq!(saturate(0), 0);
        assert_eq!(saturate(32767), 32767);
        assert_eq!(saturate(32768), 32767);
        assert_eq!(saturate(1_000_000), 32767);
        assert_eq!(saturate(-32768), -32768);
        assert_eq!(saturate(-32769), -32768);
        assert_eq!(saturate(-1_000_000), -32768);
    }
}
