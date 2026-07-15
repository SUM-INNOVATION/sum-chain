//! Frozen fixed-point integer arithmetic (plan §7), independent implementation.
//! No floating point. `isqrt` uses the bit-by-bit method (distinct from the
//! reference's Newton iteration) but yields the identical floor.

pub fn rhaz(n: i64, d: i64) -> i64 {
    debug_assert!(d > 0);
    let n = n as i128;
    let d = d as i128;
    let bias = if n >= 0 { d } else { -d };
    ((2 * n + bias) / (2 * d)) as i64
}

pub fn requantize(v: i64) -> i64 {
    rhaz(v, 256)
}

/// Bit-by-bit floor integer sqrt for `n >= 0`.
pub fn isqrt(n: i64) -> i64 {
    if n <= 0 {
        return 0;
    }
    let mut op = n as u64;
    let mut res: u64 = 0;
    let mut one: u64 = 1u64 << 62;
    while one > op {
        one >>= 2;
    }
    while one != 0 {
        if op >= res + one {
            op -= res + one;
            res = (res >> 1) + one;
        } else {
            res >>= 1;
        }
        one >>= 2;
    }
    res as i64
}

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
    fn rhaz_ties() {
        assert_eq!(rhaz(1, 2), 1);
        assert_eq!(rhaz(3, 2), 2);
        assert_eq!(rhaz(-1, 2), -1);
        assert_eq!(rhaz(-3, 2), -2);
        assert_eq!(rhaz(7, 3), 2);
        assert_eq!(rhaz(8, 3), 3);
    }

    #[test]
    fn isqrt_matches_floor() {
        for (n, r) in [
            (0, 0),
            (1, 1),
            (2, 1),
            (3, 1),
            (4, 2),
            (15, 3),
            (16, 4),
            (17, 4),
        ] {
            assert_eq!(isqrt(n), r);
        }
        for k in 1..2000i64 {
            assert_eq!(isqrt(k * k), k);
            assert_eq!(isqrt(k * k - 1), k - 1);
        }
        assert_eq!(isqrt(1_000_000_000_000), 1_000_000);
    }

    #[test]
    fn saturate_bounds() {
        assert_eq!(saturate(32768), 32767);
        assert_eq!(saturate(-32769), -32768);
        assert_eq!(saturate(5), 5);
    }
}
