//! Boundary check: the independent cross-checker must never gain a dependency
//! edge to the reference crate, or the "agreement" it proves would be circular.
//! The manifest and lockfile are inspected at compile time.
//!
//! The check targets actual dependency declarations and the lock graph — not
//! prose — so mentioning the reference crate in a comment or `description` is
//! fine, but depending on it is not.

const CARGO_TOML: &str = include_str!("../Cargo.toml");
const CARGO_LOCK: &str = include_str!("../Cargo.lock");

#[test]
fn independent_crate_does_not_depend_on_validator() {
    // Cargo.lock is the authoritative resolved dependency graph: a dependency on
    // the reference crate would appear as its own package entry.
    assert!(
        !CARGO_LOCK.contains("name = \"b0-pre-validator\""),
        "b0-pre-validator leaked into b0-pre-independent's resolved dependency graph"
    );
    // And no dependency declaration / path reference in the manifest (prose in
    // the description is allowed; a `= ...` dep line or `../` path is not).
    assert!(
        !CARGO_TOML.contains("b0-pre-validator = "),
        "b0-pre-independent declares a b0-pre-validator dependency"
    );
    assert!(
        !CARGO_TOML.contains("../b0-pre-validator"),
        "b0-pre-independent path-references the reference crate"
    );
}
