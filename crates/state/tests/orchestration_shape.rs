//! Acceptance must not be something a caller can forge or widen.
//!
//! These are source-level assertions about the acceptance API's shape. A runtime
//! test cannot say "there is no way to write this call"; what it can do is pin
//! the signatures that make the forged forms unexpressible, so a later refactor
//! that reintroduces them fails here rather than silently restoring the hole.

use std::path::Path;

fn candidate_src() -> String {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("../storage/src/candidate.rs");
    std::fs::read_to_string(p).expect("read candidate.rs")
}

/// The signature between `fn <name>` and its opening brace.
fn signature(src: &str, name: &str) -> String {
    let start = src.find(&format!("fn {name}")).unwrap_or_else(|| panic!("{name} must exist"));
    let rest = &src[start..];
    // Stop at the closing paren: everything after it is the return type, which
    // would otherwise be counted as a parameter.
    let end = rest.find(')').expect("signature must have a parameter list");
    rest[..=end].to_string()
}

#[test]
fn no_two_operand_root_comparison_exists() {
    let src = candidate_src();
    assert!(
        !src.contains("fn verify_computed_root"),
        "a two-operand root comparison reappeared; acceptance must take the block \
         and read the expected root from its header"
    );
}

/// Neither acceptance path may take a root at all.
///
/// A single `computed: Hash` parameter was not enough: a caller could pass
/// `block.header.state_root` and manufacture acceptance without using
/// execution's result. The accumulator is now BOUND at execution completion, so
/// acceptance takes only the block and there is nothing for a caller to fill in.
#[test]
fn acceptance_takes_only_the_block() {
    let src = candidate_src();
    for name in ["accept_produced", "accept_imported"] {
        let sig = signature(&src, name);
        assert!(
            sig.contains("block: &Block") || sig.contains("block: &'a Block"),
            "{name} must accept the block itself:\n{sig}"
        );
        assert!(
            !sig.contains("Hash"),
            "{name} must take NO Hash — a root parameter lets a caller supply the \
             value acceptance is supposed to check against:\n{sig}"
        );
    }
}

/// The binding itself takes the root, exactly once, on the way out of execution.
#[test]
fn the_computed_root_is_bound_at_execution_completion() {
    let src = candidate_src();
    let sig = signature(&src, "finish_execution");
    assert!(
        sig.contains("computed_root: Hash"),
        "finish_execution must take the accumulator execution produced:\n{sig}"
    );
    assert!(
        sig.contains("self,") || sig.contains("(self"),
        "finish_execution must CONSUME the candidate, so execution cannot be \
         concluded twice with different roots:\n{sig}"
    );
    assert!(
        src.contains("pub struct ExecutedCandidate"),
        "the bound root must live in its own state between execution and acceptance"
    );
}

/// The compatibility window must not be reachable from a call site.
///
/// A height parameter, or worse a boolean, would let any caller opt into
/// force-adoption. Keeping the cutoff internal means it cannot be widened from
/// outside the function that owns it.
#[test]
fn the_legacy_cutoff_cannot_be_supplied_by_a_caller() {
    let src = candidate_src();
    let sig = signature(&src, "accept_imported");
    for forbidden in ["bool", "cutoff", "legacy", "allow_", "height:"] {
        assert!(
            !sig.contains(forbidden),
            "accept_imported must not take `{forbidden}` — the compatibility window \
             is internal and cannot be opened by a caller:\n{sig}"
        );
    }
    assert!(
        src.contains("pub const LEGACY_ROOT_COMPATIBILITY_HEIGHT: BlockHeight = 496_720;"),
        "the cutoff must be a single internal constant at its existing value"
    );
}

/// Acceptance evidence must distinguish a checked root from a force-adopted one.
#[test]
fn acceptance_evidence_does_not_conflate_verified_with_adopted() {
    let src = candidate_src();
    assert!(
        !src.contains("pub struct VerifiedCandidate"),
        "a force-adopted mismatch must not be described as verified"
    );
    for variant in ["Produced", "ExactRoot", "LegacyCompatibility"] {
        assert!(src.contains(variant), "acceptance evidence must include {variant}");
    }
    assert!(
        src.contains("matches!(self, Acceptance::ExactRoot)"),
        "only an exact match may report as verified"
    );
}

/// One publisher. Both acceptance paths converge on it.
#[test]
fn exactly_one_publication_function_exists() {
    let src = candidate_src();
    assert_eq!(
        src.matches("pub fn publish").count(),
        1,
        "there must be exactly one publication function"
    );
    assert_eq!(
        src.matches("pub fn into_batch").count(),
        0,
        "no public batch escape may exist alongside the publisher"
    );
    let overlay = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../storage/src/overlay.rs"),
    )
    .expect("read overlay.rs");
    assert!(
        overlay.contains("pub(crate) fn into_batch"),
        "the overlay's batch conversion must stay crate-private, or the single \
         publisher is bypassable by constructing an overlay directly"
    );
    assert_eq!(
        overlay.matches("pub fn into_batch").count(),
        0,
        "no public batch escape may exist on the overlay"
    );
}

/// The legacy-adoption warning must follow the commit, not precede it.
///
/// A warning emitted at acceptance says a block's header root WAS adopted, and
/// would say it even when staging or the commit then failed and nothing
/// published. An operator reading logs would believe unverified state had
/// entered the chain when it had not.
///
/// This is a source-position guard, and that is what it can be: asserting "no
/// log line was emitted" needs a capturing subscriber, which this crate has no
/// reason to install. The behavioural half — that a failed publication writes
/// nothing — is covered by `a_failed_publication_emits_no_adoption_message` in
/// the storage crate.
#[test]
fn the_legacy_warning_is_emitted_only_after_the_commit() {
    let src = candidate_src();
    let commit = src
        .find("self.overlay.into_batch()?.commit()?;")
        .expect("publish must end in a commit");
    let warning = src
        .find("historical compatibility allowance")
        .expect("the legacy adoption warning must exist");
    assert!(
        warning > commit,
        "the legacy warning appears BEFORE the commit, so it would announce an \
         adoption that a later staging or commit failure prevented"
    );

    // And it must describe a completed action, not a pending one.
    assert!(
        src.contains("published a block whose computed root"),
        "the warning must read as a report of what happened, not an intention"
    );
}
