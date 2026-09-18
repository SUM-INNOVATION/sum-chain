//! The twelve remediation gates read the twelve fields they name.
//!
//! The activation audit produced thirty-three remedies. Each is a consensus
//! change, so each sits behind an activation height, and each height is read by
//! one small accessor of the shape
//!
//! ```ignore
//! fn authorization_activation(params: &ChainParams) -> Option<u64> {
//!     params.<subsystem>_authorization_enabled_from_height
//! }
//! ```
//!
//! For a while every one of those bodies was `let _ = params; None`, because the
//! fields lived in a crate the remediation pass did not own. A stub returns
//! `None`, `None` closes the gate, and a closed gate is indistinguishable at
//! runtime from a gate wired to a field an operator has not set. That is exactly
//! the shape a wiring mistake hides in: the whole subsystem behaves correctly —
//! as the unremediated binary — and every existing test passes.
//!
//! So the wiring is asserted against the source rather than against behaviour.
//! Twelve accessors, twelve fields, and the pairing between them is the claim:
//! the realistic bug in twelve near-identical three-line functions is not a
//! missing one, it is two of them reading each other's field.
//!
//! What this does NOT claim: that any gate is open, or that opening one is
//! correct. `ChainParams::default()` leaves all twelve dormant, which is pinned
//! below, and the mixed-version tests in the routing suites are what show the
//! two sides disagreeing once a height is set.

use std::collections::BTreeSet;

use sumchain_genesis::ChainParams;

/// `(source file, accessor, the field it must read)`.
///
/// Derived from the doc comment each accessor carries, which names its field.
const WIRING: &[(&str, &str, &str)] = &[
    (
        "nft_executor.rs",
        "receipt_failure_activation",
        "nft_receipt_failure_enabled_from_height",
    ),
    (
        "docclass_executor.rs",
        "stake_escrow_activation",
        "docclass_stake_escrow_enabled_from_height",
    ),
    (
        "docclass_executor.rs",
        "subject_index_split_activation",
        "docclass_subject_index_split_enabled_from_height",
    ),
    (
        "docclass_executor.rs",
        "revocation_standing_activation",
        "docclass_revocation_standing_enabled_from_height",
    ),
    (
        "healthcare_executor.rs",
        "authorization_activation",
        "healthcare_authorization_enabled_from_height",
    ),
    (
        "legal_executor.rs",
        "authorization_activation",
        "legal_authorization_enabled_from_height",
    ),
    (
        "finance_executor.rs",
        "authorization_activation",
        "finance_authorization_enabled_from_height",
    ),
    (
        "employment_executor.rs",
        "authorization_activation",
        "employment_authorization_enabled_from_height",
    ),
    (
        "property_executor.rs",
        "authorization_activation",
        "property_authorization_enabled_from_height",
    ),
    (
        "tax_executor.rs",
        "authorization_activation",
        "tax_authorization_enabled_from_height",
    ),
    (
        "lib.rs",
        "subsystem_block_timestamp_activation",
        "subsystem_block_timestamp_enabled_from_height",
    ),
    (
        "lib.rs",
        "subsystem_tx_index_activation",
        "subsystem_tx_index_enabled_from_height",
    ),
];

fn source(file: &str) -> String {
    let path = format!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/{}"), file);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {path}: {e}"))
}

/// The body of `fn <name>(params: &…ChainParams) -> Option<u64>`, by brace match.
///
/// The parameter type is matched loosely because two of the twelve write it
/// fully qualified. The RETURN type is matched exactly: an accessor that stopped
/// returning `Option<u64>` is not the thing this file is about, and should fail
/// here rather than be silently skipped.
fn accessor_body(src: &str, name: &str) -> String {
    let head = format!("fn {name}(params: &");
    let at = src
        .find(&head)
        .unwrap_or_else(|| panic!("no accessor `{name}`"));
    let ret = "-> Option<u64> {";
    let rel = src[at..]
        .find(ret)
        .unwrap_or_else(|| panic!("accessor `{name}` does not return Option<u64>"));
    let open = at + rel + ret.len() - 1;
    let bytes = src.as_bytes();
    let mut depth = 0i32;
    for (i, _) in src[open..].char_indices() {
        match bytes[open + i] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return src[open..=open + i].to_string();
                }
            }
            _ => {}
        }
    }
    panic!("unterminated body for `{name}`")
}

#[test]
fn every_remediation_gate_reads_the_field_it_names() {
    for (file, accessor, field) in WIRING {
        let body = accessor_body(&source(file), accessor);

        assert!(
            !body.contains("let _ = params;"),
            "{file}::{accessor} is still the stub that ignores its parameter, so \
             the gate can never open however the chain is configured"
        );
        assert!(
            body.contains(&format!("params.{field}")),
            "{file}::{accessor} must read `params.{field}`; body is:\n{body}"
        );

        // Exactly one field is read. Two would mean the accessor answers for a
        // gate that is not its own as well as for the one that is.
        let read: BTreeSet<&str> = WIRING
            .iter()
            .map(|(_, _, f)| *f)
            .filter(|f| body.contains(&format!("params.{f}")))
            .collect();
        assert_eq!(
            read,
            BTreeSet::from([*field]),
            "{file}::{accessor} reads {read:?}, and must read only `{field}` — \
             two of twelve near-identical accessors swapping fields is the \
             failure this pairing exists to catch"
        );
    }
}

/// The twelve fields are distinct, and there are twelve of them.
///
/// A copy-paste that left two accessors pointing at one field would satisfy the
/// pairing test above for one of them and be caught here.
///
/// It was eleven. The twelfth is `subsystem_tx_index_enabled_from_height`, and
/// its neighbour `subsystem_block_timestamp_enabled_from_height` is exactly the
/// field a copy-paste would have left it reading — which is why the count and
/// the distinctness are both asserted rather than either alone.
#[test]
fn the_twelve_gates_are_twelve_distinct_fields() {
    let fields: BTreeSet<&str> = WIRING.iter().map(|(_, _, f)| *f).collect();
    assert_eq!(
        fields.len(),
        12,
        "expected twelve distinct fields: {fields:?}"
    );
    assert_eq!(WIRING.len(), 12, "expected twelve accessors");
}

/// Wiring a gate is not opening it: the release configuration is unchanged.
///
/// This is the whole reason adding the fields is safe to do in one commit
/// separate from any decision to activate. Every gate defaults dormant, so a
/// node built from this commit executes exactly what a node built before it
/// executed, and the thirty-three audit rows stay REACHABLE until a deployed
/// `genesis.json` sets a height.
#[test]
fn every_remediation_gate_is_dormant_by_default() {
    let p = ChainParams::default();
    let dormant: Vec<(&str, Option<u64>)> = vec![
        (
            "nft_receipt_failure_enabled_from_height",
            p.nft_receipt_failure_enabled_from_height,
        ),
        (
            "docclass_stake_escrow_enabled_from_height",
            p.docclass_stake_escrow_enabled_from_height,
        ),
        (
            "docclass_subject_index_split_enabled_from_height",
            p.docclass_subject_index_split_enabled_from_height,
        ),
        (
            "docclass_revocation_standing_enabled_from_height",
            p.docclass_revocation_standing_enabled_from_height,
        ),
        (
            "healthcare_authorization_enabled_from_height",
            p.healthcare_authorization_enabled_from_height,
        ),
        (
            "legal_authorization_enabled_from_height",
            p.legal_authorization_enabled_from_height,
        ),
        (
            "finance_authorization_enabled_from_height",
            p.finance_authorization_enabled_from_height,
        ),
        (
            "employment_authorization_enabled_from_height",
            p.employment_authorization_enabled_from_height,
        ),
        (
            "property_authorization_enabled_from_height",
            p.property_authorization_enabled_from_height,
        ),
        (
            "tax_authorization_enabled_from_height",
            p.tax_authorization_enabled_from_height,
        ),
        (
            "subsystem_block_timestamp_enabled_from_height",
            p.subsystem_block_timestamp_enabled_from_height,
        ),
        (
            "subsystem_tx_index_enabled_from_height",
            p.subsystem_tx_index_enabled_from_height,
        ),
    ];
    assert_eq!(dormant.len(), WIRING.len());
    for (name, value) in dormant {
        assert_eq!(
            value, None,
            "{name} must default to dormant: activating it changes what a block \
             means, and a default is not a coordinated validator upgrade"
        );
    }
}

/// A genesis written before these fields existed still parses, and reads dormant.
///
/// `#[serde(default)]` is what makes adding twelve consensus-relevant fields a
/// non-event for every `genesis.json` already distributed. If one of them lost
/// the attribute, every existing file would fail to load — and it would fail at
/// node start, on the operator's machine, not here.
#[test]
fn a_genesis_written_before_these_fields_still_parses_dormant() {
    let full = serde_json::to_value(ChainParams::default()).expect("serialise");
    let mut stripped = full.clone();
    let obj = stripped.as_object_mut().expect("params is an object");
    for (_, _, field) in WIRING {
        assert!(
            obj.remove(*field).is_some(),
            "{field} must be serialised, or an operator cannot set it"
        );
    }
    let back: ChainParams = serde_json::from_value(stripped).expect(
        "a genesis with none of the twelve fields must still parse — this is what \
         #[serde(default)] buys, and it is checked here rather than discovered at \
         a validator's node start",
    );
    assert_eq!(back.nft_receipt_failure_enabled_from_height, None);
    assert_eq!(back.subsystem_block_timestamp_enabled_from_height, None);
    assert_eq!(back.tax_authorization_enabled_from_height, None);
    assert_eq!(back.subsystem_tx_index_enabled_from_height, None);
}
