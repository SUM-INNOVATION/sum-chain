//! THROWAWAY — branch-protection verification for issue #114 only.
//! This PR is never merged; the branch and this file are deleted after the
//! required-check behavior is confirmed. CI has no `cargo fmt --check` step, so
//! a formatting change would not fail it; a trivial failing test is used to
//! exercise the `build-test-clippy` required check, then flipped to pass.
#[test]
fn ci_required_check_probe() {
    // Flipped to passing: confirms the required build-test-clippy check now
    // reports success on the same PR (still never merged; branch+file deleted).
    assert_eq!(1 + 1, 2, "CI-gate probe now passes");
}
