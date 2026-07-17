//! Independent mirror of the B0-PRE verification-policy regressions: the two
//! frozen performance gates are enforced INDEPENDENTLY (not via the
//! 4 x 75 ms = 300 ms coincidence), and provenance self-consistency (evidence
//! integrity, not hardware eligibility) rejects impossible records.

use b0_pre_independent::closure::{
    self, decode_prov, official_qualification, provenance_eligible, qualification_failure_codes,
    qualification_gates_pass,
};

const V: &str = include_str!("../../../docs/b0-pre/fixtures/closure-golden/vectors.json");

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn valid_proving() -> closure::Prov {
    let j: serde_json::Value = serde_json::from_str(V).unwrap();
    let bytes = unhex(j["valid"]["provenance"]["bytes"].as_str().unwrap());
    decode_prov(&bytes).unwrap()
}

#[test]
fn performance_gates_are_independent() {
    // p99 within its gate but aggregate over budget (altered proof count) rejects
    assert!(!qualification_gates_pass(
        70_000_000,
        5,
        75_000_000,
        300_000_000
    ));
    // p99 over 75 ms rejects
    assert!(!qualification_gates_pass(
        76_000_000,
        4,
        75_000_000,
        300_000_000
    ));
    // aggregate exactly at budget passes -- frozen (4 * 75 ms) and altered (5 * 60 ms)
    assert!(official_qualification(75_000_000));
    assert!(qualification_gates_pass(
        60_000_000,
        5,
        75_000_000,
        300_000_000
    ));
    // checked multiplication overflow rejects (huge p99 with a huge p99-gate)
    assert!(!qualification_gates_pass(
        u64::MAX / 2,
        4,
        u64::MAX,
        300_000_000
    ));
    // over-gate fails BOTH frozen gates; a qualifying p99 yields no codes
    assert_eq!(qualification_failure_codes(76_000_000), vec![3, 4]);
    assert!(qualification_failure_codes(59_000_000).is_empty());
}

#[test]
fn provenance_self_consistency_rejects_impossible_records() {
    // the valid proving-role reference provenance passes
    assert_eq!(provenance_eligible(&valid_proving()), Ok(()));

    // configured cpuset exceeding detected logical CPUs is malformed
    let mut cpuset_over = valid_proving();
    cpuset_over.cpuset = cpuset_over.logical + 1;
    assert_eq!(
        provenance_eligible(&cpuset_over),
        Err("cpuset_exceeds_logical")
    );
    // configured memory limit exceeding detected RAM is malformed
    let mut mem_over = valid_proving();
    mem_over.memlimit = mem_over.ram + 1;
    assert_eq!(provenance_eligible(&mem_over), Err("memlimit_exceeds_ram"));
    // a zero resource value is malformed
    let mut zero = valid_proving();
    zero.cpuset = 0;
    assert_eq!(provenance_eligible(&zero), Err("zero_resource"));
}
