//! Domain tags (plan §3).
//!
//! Two families:
//!  * **Structured 32-byte tags** — an ASCII string zero-padded to 32 bytes. Used
//!    as the leading field of a canonical binary structure; decoders compare the
//!    32 bytes to the frozen constant, so any non-zero trailing padding fails.
//!  * **Variable-length hash-prefix tags** — literal byte strings (exact `\0` or
//!    `\n` terminator) prepended to a BLAKE3 preimage; never zero-padded.

/// Zero-pad an ASCII tag to a 32-byte array at compile time. Panics (const) if
/// the string is longer than 32 bytes, so an over-long tag cannot be defined.
pub const fn pad32(s: &[u8]) -> [u8; 32] {
    assert!(s.len() <= 32, "structured domain tag exceeds 32 bytes");
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < s.len() {
        out[i] = s[i];
        i += 1;
    }
    out
}

// --- Structured 32-byte domain tags ---
pub const OBJECT_TAG: [u8; 32] = pad32(b"SUMCHAIN/R0/OBJECT/v1");
pub const STATEMENT_TAG: [u8; 32] = pad32(b"SUMCHAIN/R0/STATEMENT/v2");
pub const ENVELOPE_TAG: [u8; 32] = pad32(b"SUMCHAIN/R0/ENVELOPE/v1");
pub const OUTPUT_MANIFEST_TAG: [u8; 32] = pad32(b"SUMCHAIN/R0/MANIFEST/v1");
pub const INPUT_MANIFEST_TAG: [u8; 32] = pad32(b"SUMCHAIN/R0/INMANIFEST/v1");
pub const BENCH_SAMPLE_TAG: [u8; 32] = pad32(b"SUMCHAIN/R0/BENCH/v1");
pub const BENCH_RSS_TAG: [u8; 32] = pad32(b"SUMCHAIN/R0/BENCHRSS/v1");
pub const RESEARCH_CHAIN_TAG: [u8; 32] = pad32(b"SUMCHAIN/R0/RCHAIN/v1");
pub const DERIVED_INPUT_TAG: [u8; 32] = pad32(b"SUMCHAIN/R0/DERIVIN/v1");
pub const EXP_TABLE_TAG: [u8; 32] = pad32(b"SUMCHAIN/B0PRE/EXP/v1");
pub const EXP_CERT_TAG: [u8; 32] = pad32(b"SUMCHAIN/B0PRE/EXPCERT/v1");
pub const VERIFIER_MATERIAL_TAG: [u8; 32] = pad32(b"SUMCHAIN/B0PRE/VMAT/v1");
pub const CARGO_LOCK_TAG: [u8; 32] = pad32(b"SUMCHAIN/B0PRE/CARGOLOCK/v1");
pub const CONTAINER_TAG: [u8; 32] = pad32(b"SUMCHAIN/B0PRE/CONTAINER/v1");

// --- Variable-length hash-prefix tags (exact terminator; not zero-padded) ---
pub const FIXTURE_PREFIX: &[u8] = b"SUMCHAIN/B0-PRE/FIXTURE/v1\0";
pub const ID_PREFIX: &[u8] = b"SUMCHAIN/B0-PRE/ID/v1\0";
pub const DATA_PREFIX: &[u8] = b"SUMCHAIN/B0-PRE/DATA/v1\0";
pub const SPEC_PREFIX: &[u8] = b"SUMCHAIN/B0-PRE/SPEC/v1\n";
pub const STMT_TEMPLATE_PREFIX: &[u8] = b"SUMCHAIN/R0/STMTTEMPLATE/v2\n";
pub const GUESTSET_PREFIX: &[u8] = b"SUMCHAIN/R0/GUESTSET/v1\n";
pub const GUESTSRC_PREFIX: &[u8] = b"SUMCHAIN/R0/GUESTSRC/v1\n";
pub const BUILDCMD_PREFIX: &[u8] = b"SUMCHAIN/R0/BUILDCMD/v1\n";
pub const ARCHPROV_PREFIX: &[u8] = b"SUMCHAIN/R0/ARCHPROV/v1\n";
pub const RESULTSET_PREFIX: &[u8] = b"SUMCHAIN/R0/RESULTSET/v1\n";
pub const HARNESS_PREFIX: &[u8] = b"SUMCHAIN/R0/HARNESSSRC/v1\n";
pub const ENVCAP_PREFIX: &[u8] = b"SUMCHAIN/R0/ENVCAP/v1\n";
pub const SAMPLEBUNDLE_PREFIX: &[u8] = b"SUMCHAIN/R0/SAMPLEBUNDLE/v1\n";
pub const RSSBUNDLE_PREFIX: &[u8] = b"SUMCHAIN/R0/RSSBUNDLE/v1\n";

/// The logical (unpadded) length of a structured tag: the index of the first
/// zero byte. All bytes at and after it must be zero for the padding to be well
/// formed; `well_padded` checks exactly that.
pub fn ascii_len(tag: &[u8; 32]) -> usize {
    tag.iter().position(|&b| b == 0).unwrap_or(32)
}

/// True iff `tag` is a non-empty ASCII string followed only by zero padding.
pub fn well_padded(tag: &[u8; 32]) -> bool {
    let n = ascii_len(tag);
    if n == 0 {
        return false;
    }
    tag[..n].iter().all(|&b| (0x20..=0x7E).contains(&b)) && tag[n..].iter().all(|&b| b == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_STRUCTURED: &[(&str, [u8; 32])] = &[
        ("OBJECT", OBJECT_TAG),
        ("STATEMENT", STATEMENT_TAG),
        ("ENVELOPE", ENVELOPE_TAG),
        ("OUTPUT_MANIFEST", OUTPUT_MANIFEST_TAG),
        ("INPUT_MANIFEST", INPUT_MANIFEST_TAG),
        ("BENCH_SAMPLE", BENCH_SAMPLE_TAG),
        ("BENCH_RSS", BENCH_RSS_TAG),
        ("RESEARCH_CHAIN", RESEARCH_CHAIN_TAG),
        ("DERIVED_INPUT", DERIVED_INPUT_TAG),
        ("EXP_TABLE", EXP_TABLE_TAG),
        ("EXP_CERT", EXP_CERT_TAG),
        ("VERIFIER_MATERIAL", VERIFIER_MATERIAL_TAG),
        ("CARGO_LOCK", CARGO_LOCK_TAG),
        ("CONTAINER", CONTAINER_TAG),
    ];

    #[test]
    fn pad32_zero_pads_and_preserves_prefix() {
        let t = pad32(b"abc");
        assert_eq!(&t[..3], b"abc");
        assert!(t[3..].iter().all(|&b| b == 0));
    }

    #[test]
    fn every_structured_tag_is_well_padded_and_bounded() {
        for (name, tag) in ALL_STRUCTURED {
            assert!(well_padded(tag), "{name} not well padded");
            assert!(ascii_len(tag) <= 32, "{name} too long");
        }
    }

    #[test]
    fn structured_tags_are_all_distinct() {
        for (i, (na, a)) in ALL_STRUCTURED.iter().enumerate() {
            for (nb, b) in &ALL_STRUCTURED[i + 1..] {
                assert_ne!(a, b, "tag collision {na} vs {nb}");
            }
        }
    }

    #[test]
    fn nonzero_trailing_padding_is_not_well_padded() {
        let mut t = OBJECT_TAG;
        t[31] = 0x01; // corrupt the padding
        assert!(!well_padded(&t));
        assert_ne!(t, OBJECT_TAG); // and it no longer matches the frozen constant
    }

    #[test]
    fn variable_prefixes_have_exact_terminators() {
        assert_eq!(*FIXTURE_PREFIX.last().unwrap(), 0u8);
        assert_eq!(*ID_PREFIX.last().unwrap(), 0u8);
        assert_eq!(*DATA_PREFIX.last().unwrap(), 0u8);
        assert_eq!(*SPEC_PREFIX.last().unwrap(), b'\n');
        assert_eq!(*STMT_TEMPLATE_PREFIX.last().unwrap(), b'\n');
        assert_eq!(*GUESTSET_PREFIX.last().unwrap(), b'\n');
        assert_eq!(*RESULTSET_PREFIX.last().unwrap(), b'\n');
        assert_eq!(*ARCHPROV_PREFIX.last().unwrap(), b'\n');
    }
}
