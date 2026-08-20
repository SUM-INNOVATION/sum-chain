//! Real-vector cross-check: the venue-produced authority JSONs (emitted by `lib.sh`) must recompute to
//! the SAME domain-separated address in Rust — proving the validator's from-scratch recomputation
//! mirrors lib.sh byte-for-byte. The fixtures are the actual x86 venue outputs (RISC0 two-graph
//! dependency seed + native host-toolchain attestation).

use b0_pre_validator::venue::dependency_seed::DependencySeedV1;
use b0_pre_validator::venue::host_toolchain::HostToolchainAttestationV1;

const REAL_DEP_SEED_ADDR: &str = "2f5b1cd11b13dbd26ba1251dbac47c94dd680c1a3293309ae5b9a79102222308";
const REAL_HOST_TC_ADDR: &str = "53e760bfa246b90712b8aa7a91634237506b06734b0731481484d0ac197714fe";

#[test]
fn real_risc0_dependency_seed_recomputes_to_libsh_address() {
    let bytes = include_bytes!("fixtures/real_dep_seed_risc0.json");
    let d = DependencySeedV1::from_json(bytes).expect("parse real dep-seed");
    assert_eq!(d.address, REAL_DEP_SEED_ADDR, "fixture drifted");
    // The Rust recomputation must EQUAL the lib.sh-recorded address, byte-for-byte.
    assert_eq!(d.recompute_address(), REAL_DEP_SEED_ADDR);
    // Full verify (shape + per-candidate graph/unit expectations + address) must pass.
    d.verify("risc0").expect("verify real risc0 dep-seed");
}

#[test]
fn real_x86_host_toolchain_recomputes_to_libsh_address() {
    let bytes = include_bytes!("fixtures/real_host_toolchain_x86.json");
    let d = HostToolchainAttestationV1::from_json(bytes).expect("parse real host-tc");
    assert_eq!(d.address, REAL_HOST_TC_ADDR, "fixture drifted");
    assert_eq!(d.recompute_address(), REAL_HOST_TC_ADDR);
    d.verify("x86_64", Some("1.90.0"))
        .expect("verify real x86 host-tc");
}
