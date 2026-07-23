//! Certified Q16 exp-table lookup (plan §6), guest form.
//!
//! The frozen reference `b0-pre-validator/src/exp.rs` *certifies and generates*
//! the table with bignum interval arithmetic — far too heavy for a zkVM guest.
//! The guest only needs the frozen VALUES and the lookup rule, so the certified
//! values are baked in as [`exp_table::EXP_TABLE`] (a verbatim copy of the
//! committed `docs/b0-pre/exp/exp_table_q16.json` `table`), and this module
//! exposes only the frozen lookup. `tests/exp_table_binding.rs` binds the baked
//! values to the committed artifact + its `.hash`, so drift cannot pass silently.

pub use crate::exp_table::{EXP_TABLE, SCALE_BITS, TABLE_LEN, Z_MAX};

/// The frozen table as a slice, for callers that pass `&[u32]` (mirrors the
/// reference `exp::table_cached()` signature).
pub fn table() -> &'static [u32] {
    &EXP_TABLE
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
    fn table_shape_and_lookup_boundaries() {
        assert_eq!(EXP_TABLE.len(), TABLE_LEN);
        assert_eq!(SCALE_BITS, 16);
        assert_eq!(EXP_TABLE[0], 65536);
        assert!(EXP_TABLE[3016] >= 1);
        let t = table();
        assert_eq!(lookup(t, 0), 65536);
        assert_eq!(lookup(t, Z_MAX), t[3016]);
        assert_eq!(lookup(t, Z_MAX + 1), 0);
        assert_eq!(lookup(t, 10_000), 0);
    }

    #[test]
    fn table_is_monotone_non_increasing() {
        for i in 1..EXP_TABLE.len() {
            assert!(EXP_TABLE[i] <= EXP_TABLE[i - 1], "not monotone at {i}");
        }
    }
}
