//! The production entry point must not let a caller supply the comparison.
//!
//! `verify_computed_root(h, h)` succeeds — that call is a mechanism, and its own
//! documentation says so. The guarantee lives in the orchestration API, which
//! must make the forged shape unexpressible rather than merely discouraged.
//!
//! These are source-level assertions about the signature. A runtime test cannot
//! state "there is no way to write this call"; what it can do is pin the shape
//! that makes it impossible, so a later refactor that reintroduces hash operands
//! fails here rather than silently restoring the hole.

use std::path::Path;

fn source() -> String {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/candidate_block.rs");
    std::fs::read_to_string(p).expect("read candidate_block.rs")
}

/// The signature between `pub fn execute_candidate_block` and its opening brace.
fn entry_point_signature(src: &str) -> String {
    let start = src
        .find("fn execute_candidate_block")
        .expect("entry point must exist");
    let rest = &src[start..];
    let end = rest.find("{").expect("signature must end in a brace");
    rest[..end].to_string()
}

#[test]
fn the_entry_point_takes_the_block_and_no_expected_root() {
    let src = source();
    let sig = entry_point_signature(&src);

    assert!(
        sig.contains("block: &Block"),
        "the entry point must accept the block itself:\n{sig}"
    );

    // `parent_state_root` is an input to execution, not an operand of the
    // comparison — it is what the accumulator chains FROM. Everything else
    // hash-shaped would be a caller-supplied side of the equality.
    let hash_params: Vec<&str> = sig
        .lines()
        .map(str::trim)
        .filter(|l| l.contains(": Hash"))
        .collect();
    assert_eq!(
        hash_params,
        vec!["parent_state_root: Hash,"],
        "the only Hash parameter may be the parent root that execution chains \
         from. A `computed` or `expected` parameter would let a caller pass the \
         header's root as both operands, which is exactly the forgery this \
         entry point exists to prevent. Found:\n{hash_params:?}"
    );
}

#[test]
fn the_entry_point_reads_the_declared_root_from_the_header_itself() {
    let src = source();
    assert!(
        src.contains("verify_for_block(block, computed_root)"),
        "the expected root must be read from the block inside verification, not \
         received as a parameter"
    );
    assert!(
        src.contains("executor.execute_block("),
        "the computed root must come from execution inside this function"
    );
}

/// The entry point must stay crate-private until execution actually runs
/// through an `ExecutionView`.
///
/// Today it creates a candidate and never opens `view()`: it calls the committed
/// executor, which writes through its own database handles, then verifies an
/// overlay that is empty because nothing was written to it. Exporting that would
/// invite callers to read "candidate execution" as meaning a rejected block
/// leaves no trace, which is false. This fails the moment someone makes it `pub`
/// without also routing execution.
#[test]
fn the_scaffolding_entry_point_is_not_public() {
    let src = source();
    assert!(
        src.contains("pub(crate) fn execute_candidate_block"),
        "execute_candidate_block must remain pub(crate) while it still bypasses \
         the ExecutionView"
    );
    assert!(
        !src.contains("\npub fn execute_candidate_block"),
        "execute_candidate_block must not be exported"
    );
    assert!(
        src.contains("SCAFFOLDING"),
        "the module must say plainly that isolation is absent"
    );
}

/// And when it IS routed, this test is the reminder to re-check the claim.
#[test]
fn routing_through_the_view_is_still_outstanding() {
    let src = source();
    let routed = src.contains("candidate.view()") || src.contains(".view();");
    assert!(
        !routed,
        "execution now opens a view — good. Update this test and \
         `the_scaffolding_entry_point_is_not_public` together with whatever \
         evidence shows every execution path uses it, then the entry point may \
         become public."
    );
}

/// The forgeable comparison must not exist at all — not merely be private.
///
/// A `verify(computed, expected)` taking two caller-supplied hashes proves a
/// comparison occurred and nothing about where either side came from:
/// `verify(h, h)` succeeds. Making it crate-private would still leave it
/// reachable from every future caller inside the storage crate, so it was
/// deleted. Verification reads the expected root from the block.
#[test]
fn no_two_operand_root_comparison_exists() {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("../storage/src/candidate.rs");
    let src = std::fs::read_to_string(p).expect("read candidate.rs");

    assert!(
        !src.contains("fn verify_computed_root"),
        "a two-operand root comparison reappeared; verification must take the \
         block and read the expected root from its header"
    );
    assert!(
        src.contains("pub fn verify_for_block"),
        "verify_for_block must be the verification path"
    );
    assert!(
        src.contains("let declared = block.header.state_root;"),
        "the expected root must be read from the block inside verification"
    );
}

