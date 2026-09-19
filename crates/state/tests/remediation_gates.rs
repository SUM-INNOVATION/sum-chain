//! The nineteen remediation gates read the nineteen fields they name.
//!
//! The activation audit produced a set of remedies, and it is still growing.
//! Each is a consensus change, so each sits behind an activation height, and
//! each height is read by one small accessor of the shape
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
//! Nineteen accessors, nineteen fields, and the PAIRING between them is the
//! claim: the realistic bug in nineteen near-identical three-line functions is
//! not a missing one, it is two of them reading each other's field.
//!
//! That is not hypothetical. Making one accessor read its neighbour's field was
//! killed by `every_remediation_gate_reads_the_field_it_names` while the
//! behavioural suite for that subsystem still reported every test passing. And
//! the hazard is getting closer rather than further away: two files now declare
//! TWO accessors apiece — `tax_executor.rs` has `authorization_activation` and
//! `proof_lifecycle_activation`, `healthcare_executor.rs` has
//! `authorization_activation` and `state_precondition_activation` — so a swap
//! there does not even cross a file boundary.
//!
//! A third reason this table earns its keep: it is the thing that catches a
//! GATE LOST IN A MERGE. Two branches that each add gates here conflict in the
//! middle of an entry, and a resolution that splices the halves together yields
//! a table that still parses and is two gates short. The count assertions found
//! exactly that.
//!
//! What this does NOT claim: that any gate is open, or that opening one is
//! correct. `ChainParams::default()` leaves all nineteen dormant, which is
//! pinned below, and the mixed-version tests in the routing suites are what show
//! the two sides disagreeing once a height is set.

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
    (
        "lib.rs",
        "subsystem_allocation_bound_activation",
        "subsystem_allocation_bound_enabled_from_height",
    ),
    (
        "tax_executor.rs",
        "proof_lifecycle_activation",
        "tax_proof_lifecycle_enabled_from_height",
    ),
    (
        "nft_executor.rs",
        "token_authority_activation",
        "nft_token_authority_enabled_from_height",
    ),
    (
        "agreement_executor.rs",
        "signature_integrity_activation",
        "agreement_signature_integrity_enabled_from_height",
    ),
    (
        "healthcare_executor.rs",
        "state_precondition_activation",
        "healthcare_state_precondition_enabled_from_height",
    ),
    (
        "lib.rs",
        "subsystem_proof_presence_activation",
        "subsystem_proof_presence_enabled_from_height",
    ),
    (
        "nft_executor.rs",
        "update_path_parity_activation",
        "nft_update_path_parity_enabled_from_height",
    ),
];

fn source(file: &str) -> String {
    let path = format!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/{}"), file);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {path}: {e}"))
}

/// The body of `fn <name>(params: &…ChainParams) -> Option<u64>`, by brace match.
///
/// The parameter type is matched loosely because some of the nineteen write it
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
             two of nineteen near-identical accessors swapping fields is the \
             failure this pairing exists to catch"
        );
    }
}

/// The nineteen fields are distinct, and there are nineteen of them.
///
/// A copy-paste that left two accessors pointing at one field would satisfy the
/// pairing test above for one of them and be caught here.
///
/// It was eleven, then twelve, then thirteen, then seventeen, then eighteen,
/// and now nineteen.
///
/// The twelfth was `subsystem_tx_index_enabled_from_height`, whose neighbour
/// `subsystem_block_timestamp_enabled_from_height` is exactly the field a
/// copy-paste would have left it reading — which is why the count and the
/// distinctness are both asserted rather than either alone. The thirteenth,
/// `subsystem_allocation_bound_enabled_from_height`, is a third `subsystem_`
/// gate declared beside those two and reading neither. The last four arrived
/// together, and two of them are a SECOND accessor in a file that already had
/// one (`tax_executor.rs`, `healthcare_executor.rs`), which is the same hazard
/// one step closer: a swap there does not even cross a file boundary. The
/// eighteenth, `subsystem_proof_presence_activation`, is a FOURTH `lib.rs`
/// accessor sitting beside three others whose names all begin `subsystem_`, and
/// the nineteenth, `update_path_parity_activation`, is a THIRD accessor in
/// `nft_executor.rs`.
///
/// That hazard is not hypothetical here. Making one accessor read its
/// neighbour's field was killed by `every_remediation_gate_reads_the_field_it_names`
/// while the behavioural suite for that subsystem still reported every test
/// passing.
#[test]
fn the_nineteen_gates_are_nineteen_distinct_fields() {
    let fields: BTreeSet<&str> = WIRING.iter().map(|(_, _, f)| *f).collect();
    assert_eq!(
        fields.len(),
        19,
        "expected nineteen distinct fields: {fields:?}"
    );
    assert_eq!(WIRING.len(), 19, "expected nineteen accessors");
}

/// Wiring a gate is not opening it: the release configuration is unchanged.
///
/// This is the whole reason adding the fields is safe to do in one commit
/// separate from any decision to activate. Every gate defaults dormant, so a
/// node built from this commit executes exactly what a node built before it
/// executed, and every audit row behind one of them stays REACHABLE until a
/// deployed `genesis.json` sets a height.
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
        (
            "subsystem_allocation_bound_enabled_from_height",
            p.subsystem_allocation_bound_enabled_from_height,
        ),
        (
            "tax_proof_lifecycle_enabled_from_height",
            p.tax_proof_lifecycle_enabled_from_height,
        ),
        (
            "nft_token_authority_enabled_from_height",
            p.nft_token_authority_enabled_from_height,
        ),
        (
            "agreement_signature_integrity_enabled_from_height",
            p.agreement_signature_integrity_enabled_from_height,
        ),
        (
            "healthcare_state_precondition_enabled_from_height",
            p.healthcare_state_precondition_enabled_from_height,
        ),
        (
            "subsystem_proof_presence_enabled_from_height",
            p.subsystem_proof_presence_enabled_from_height,
        ),
        (
            "nft_update_path_parity_enabled_from_height",
            p.nft_update_path_parity_enabled_from_height,
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
/// `#[serde(default)]` is what makes adding nineteen consensus-relevant fields a
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
        "a genesis with none of the nineteen fields must still parse — this is what \
         #[serde(default)] buys, and it is checked here rather than discovered at \
         a validator's node start",
    );
    assert_eq!(back.nft_receipt_failure_enabled_from_height, None);
    assert_eq!(back.subsystem_block_timestamp_enabled_from_height, None);
    assert_eq!(back.tax_authorization_enabled_from_height, None);
    assert_eq!(back.subsystem_tx_index_enabled_from_height, None);
    assert_eq!(back.subsystem_allocation_bound_enabled_from_height, None);
    assert_eq!(back.tax_proof_lifecycle_enabled_from_height, None);
    assert_eq!(back.nft_token_authority_enabled_from_height, None);
    assert_eq!(back.agreement_signature_integrity_enabled_from_height, None);
    assert_eq!(back.healthcare_state_precondition_enabled_from_height, None);
    assert_eq!(back.subsystem_proof_presence_enabled_from_height, None);
    assert_eq!(back.nft_update_path_parity_enabled_from_height, None);
}
