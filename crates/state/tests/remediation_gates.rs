//! The twenty-five remediation gates read the twenty-five fields they name.
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
//! Twenty-five accessors, twenty-five fields, and the PAIRING between them
//! is the claim: the realistic bug in twenty-five near-identical three-line
//! functions is
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
//! correct. `ChainParams::default()` leaves all twenty-five dormant, which is
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
    (
        "lib.rs",
        "subsystem_no_op_receipt_activation",
        "subsystem_no_op_receipt_enabled_from_height",
    ),
    (
        "docclass_executor.rs",
        "issuer_authority_activation",
        "docclass_issuer_authority_enabled_from_height",
    ),
    (
        "docclass_executor.rs",
        "revocation_record_activation",
        "docclass_revocation_record_enabled_from_height",
    ),
    (
        "docclass_executor.rs",
        "credential_schema_activation",
        "docclass_credential_schema_enabled_from_height",
    ),
    (
        "docclass_executor.rs",
        "identity_binding_activation",
        "docclass_identity_binding_enabled_from_height",
    ),
    (
        "docclass_executor.rs",
        "issuer_stake_requirement_activation",
        "docclass_issuer_stake_requirement_enabled_from_height",
    ),
];

fn source(file: &str) -> String {
    let path = format!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/{}"), file);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {path}: {e}"))
}

/// The body of `fn <name>(params: &…ChainParams) -> Option<u64>`, by brace match.
///
/// The parameter type is matched loosely because some of the twenty-five write it
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
             two of twenty-five near-identical accessors swapping fields is the \
             failure this pairing exists to catch"
        );
    }
}

/// The twenty-five fields are distinct, and there are twenty-five of them.
///
/// A copy-paste that left two accessors pointing at one field would satisfy the
/// pairing test above for one of them and be caught here.
///
/// It was eleven, then twelve, then thirteen, then seventeen, then eighteen,
/// then nineteen, then twenty, then twenty-three, and now twenty-five.
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
/// `nft_executor.rs`. The twentieth, `subsystem_no_op_receipt_activation`, is a
/// FIFTH `lib.rs` accessor. The twenty-first, twenty-second and twenty-third
/// arrived together and are all three in `docclass_executor.rs`, and the
/// twenty-fourth and twenty-fifth are in that file too, taking it from three
/// accessors to EIGHT — the densest the hazard has ever been, and the reason
/// the pairing is asserted per accessor rather than per file.
///
/// That hazard is not hypothetical here. Making one accessor read its
/// neighbour's field was killed by `every_remediation_gate_reads_the_field_it_names`
/// while the behavioural suite for that subsystem still reported every test
/// passing.
#[test]
fn the_twenty_five_gates_are_twenty_five_distinct_fields() {
    let fields: BTreeSet<&str> = WIRING.iter().map(|(_, _, f)| *f).collect();
    assert_eq!(
        fields.len(),
        25,
        "expected twenty-five distinct fields: {fields:?}"
    );
    assert_eq!(WIRING.len(), 25, "expected twenty-five accessors");
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
        (
            "subsystem_no_op_receipt_enabled_from_height",
            p.subsystem_no_op_receipt_enabled_from_height,
        ),
        (
            "docclass_issuer_authority_enabled_from_height",
            p.docclass_issuer_authority_enabled_from_height,
        ),
        (
            "docclass_revocation_record_enabled_from_height",
            p.docclass_revocation_record_enabled_from_height,
        ),
        (
            "docclass_credential_schema_enabled_from_height",
            p.docclass_credential_schema_enabled_from_height,
        ),
        (
            "docclass_identity_binding_enabled_from_height",
            p.docclass_identity_binding_enabled_from_height,
        ),
        (
            "docclass_issuer_stake_requirement_enabled_from_height",
            p.docclass_issuer_stake_requirement_enabled_from_height,
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
/// `#[serde(default)]` is what makes adding twenty-five consensus-relevant fields a
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
        "a genesis with none of the twenty-five fields must still parse — this is what \
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
    assert_eq!(back.subsystem_no_op_receipt_enabled_from_height, None);
    assert_eq!(back.docclass_issuer_authority_enabled_from_height, None);
    assert_eq!(back.docclass_revocation_record_enabled_from_height, None);
    assert_eq!(back.docclass_credential_schema_enabled_from_height, None);
    assert_eq!(back.docclass_identity_binding_enabled_from_height, None);
    assert_eq!(
        back.docclass_issuer_stake_requirement_enabled_from_height,
        None
    );
}

/// `sumchain_genesis::REMEDIATION_GATES` names exactly these twenty fields.
///
/// A second list of the same twenty gates now exists in
/// `crates/genesis/src/lib.rs`, because
/// `ChainParams::peer_protocol_declaration_required_from_height` has to be at
/// or below the FIRST of them and no other list in that file can answer which
/// one that is — `activation_heights()` also covers gates a live chain may
/// legitimately have passed long ago.
///
/// Two lists is one more than is safe, so they are pinned to each other. The
/// direction that matters is a gate added HERE and not there: the remediation
/// pass adds a gate, an executor starts changing behaviour at a height, and the
/// enforcement deadline does not see it — which is the whole defect this
/// mechanism exists to close, reintroduced through the list that configures it.
///
/// It is also the third place the merge hazard in this file's header can bite.
/// A resolution that splices two entries together leaves a list that still
/// parses and is one gate short; the set comparison names the missing one
/// rather than reporting a count.
#[test]
fn the_genesis_gate_list_matches_the_accessor_table() {
    let wired: BTreeSet<&str> = WIRING.iter().map(|(_, _, f)| *f).collect();
    let in_genesis: BTreeSet<&str> = sumchain_genesis::REMEDIATION_GATES
        .iter()
        .copied()
        .collect();

    let missing: Vec<_> = wired.difference(&in_genesis).collect();
    assert!(
        missing.is_empty(),
        "these gates are read by an executor and are NOT in \
         sumchain_genesis::REMEDIATION_GATES, so opening one would not oblige an \
         operator to set peer_protocol_declaration_required_from_height and the \
         rules would diverge while undeclared peers were still admitted: {missing:?}"
    );
    let stale: Vec<_> = in_genesis.difference(&wired).collect();
    assert!(
        stale.is_empty(),
        "these names are in sumchain_genesis::REMEDIATION_GATES and no accessor \
         reads them; either a gate was renamed on one side only, or the \
         enforcement deadline is being set by a gate that does nothing: {stale:?}"
    );
    assert_eq!(in_genesis.len(), 20);
}
