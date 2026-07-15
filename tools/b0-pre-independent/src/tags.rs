//! Domain tags needed by the independent spec-hash pipeline (documented values,
//! independently constructed).

const fn t(s: &[u8]) -> [u8; 32] {
    let mut o = [0u8; 32];
    let mut i = 0;
    while i < s.len() {
        o[i] = s[i];
        i += 1;
    }
    o
}

pub const OBJECT: [u8; 32] = t(b"SUMCHAIN/R0/OBJECT/v1");
pub const STATEMENT: [u8; 32] = t(b"SUMCHAIN/R0/STATEMENT/v2");
pub const OUTPUT_MANIFEST: [u8; 32] = t(b"SUMCHAIN/R0/MANIFEST/v1");
pub const INPUT_MANIFEST: [u8; 32] = t(b"SUMCHAIN/R0/INMANIFEST/v1");
pub const RESEARCH_CHAIN: [u8; 32] = t(b"SUMCHAIN/R0/RCHAIN/v1");
pub const DERIVED_INPUT: [u8; 32] = t(b"SUMCHAIN/R0/DERIVIN/v1");
pub const ENVELOPE: [u8; 32] = t(b"SUMCHAIN/R0/ENVELOPE/v1");
pub const BENCH_SAMPLE: [u8; 32] = t(b"SUMCHAIN/R0/BENCH/v1");
pub const BENCH_RSS: [u8; 32] = t(b"SUMCHAIN/R0/BENCHRSS/v1");
pub const VERIFIER_MATERIAL: [u8; 32] = t(b"SUMCHAIN/B0PRE/VMAT/v1");

pub const STMT_TEMPLATE_PREFIX: &[u8] = b"SUMCHAIN/R0/STMTTEMPLATE/v2\n";
pub const GUESTSET_PREFIX: &[u8] = b"SUMCHAIN/R0/GUESTSET/v1\n";
pub const ARCHPROV_PREFIX: &[u8] = b"SUMCHAIN/R0/ARCHPROV/v1\n";
pub const RESULTSET_PREFIX: &[u8] = b"SUMCHAIN/R0/RESULTSET/v1\n";
pub const SAMPLEBUNDLE_PREFIX: &[u8] = b"SUMCHAIN/R0/SAMPLEBUNDLE/v1\n";
pub const RSSBUNDLE_PREFIX: &[u8] = b"SUMCHAIN/R0/RSSBUNDLE/v1\n";
