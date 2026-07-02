//! Issue #50 Phase 4: hard guard that the registered `gov_*` RPC surface is
//! exactly the approved 11 methods (4 unsigned-tx builders + 7 reads) — and in
//! particular that no private-key / direct-write governance method exists.
//! (P6a added the `gov_buildCancelProposal` builder.)
//!
//! Documented `gov_*` method-name validation (documented ⊆ registered) lives in
//! the shared `docs_tax_methods` drift guard, extended for `gov_` in P5. This
//! file keeps the exact-surface + no-private-key guards.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

fn collect(text: &str, needle: &str, prefix: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for (idx, _) in text.match_indices(needle) {
        let rest = &text[idx + needle.len()..];
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if name.starts_with(prefix) {
            out.insert(name);
        }
    }
    out
}

fn read(rel: &str) -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    fs::read_to_string(p).unwrap_or_else(|_| panic!("read {}", rel))
}

/// The exact approved governance surface: builders (no keys) + reads.
const ALLOWED: [&str; 11] = [
    "gov_buildCreateProposal",
    "gov_buildCastVote",
    "gov_buildExecuteProposal",
    "gov_buildCancelProposal",
    "gov_getProposal",
    "gov_listProposals",
    "gov_listActiveProposals",
    "gov_getTally",
    "gov_getVote",
    "gov_getVotingPower",
    "gov_listEligibleAssets",
];

#[test]
fn governance_surface_is_exactly_the_approved_set() {
    let api = read("src/api.rs");
    let registered = collect(&api, "name = \"", "gov_");
    let allowed: BTreeSet<String> = ALLOWED.iter().map(|s| s.to_string()).collect();

    // Any gov_* method outside the approved set fails — including private-key /
    // direct-write methods (e.g. gov_createProposal, gov_castVote, gov_sign*,
    // gov_submit*), which must never exist (writes go through the builders +
    // sum_sendRawTransaction).
    let extra: Vec<_> = registered.difference(&allowed).cloned().collect();
    assert!(extra.is_empty(), "unexpected gov_* RPC methods registered: {:?}", extra);
    assert_eq!(registered, allowed, "gov_* surface must be exactly the 11 approved methods");
}

#[test]
fn no_private_key_style_governance_methods() {
    let api = read("src/api.rs");
    // Defensive: the write path is builder-only. Guard against obviously
    // key-accepting or direct-write governance method names.
    for banned in ["gov_signAndSubmit", "gov_createProposal", "gov_castVote", "gov_executeProposal", "gov_submit"] {
        assert!(
            !api.contains(&format!("name = \"{banned}\"")),
            "private-key/direct-write governance method must not exist: {banned}"
        );
    }
}
