//! THROWAWAY — branch-protection verification for issue #114 only.
//! This PR is never merged; the branch and this file are deleted after the
//! required-check behavior is confirmed. CI has no `cargo fmt --check` step, so
//! a formatting change would not fail it; a trivial failing test is used to
//! exercise the `build-test-clippy` required check, then flipped to pass.
#[test]
fn ci_required_check_probe() {
    // Intentional failure to confirm build-test-clippy blocks merge; will be
    // flipped to `2` to confirm the required check then passes.
    assert_eq!(1 + 1, 3, "intentional CI-gate probe failure");
}
