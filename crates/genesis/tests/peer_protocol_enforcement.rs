//! `peer_protocol_declaration_required_from_height`: the height at which a peer
//! that has declared nothing stops being allowed to take part in consensus.
//!
//! # What it is for
//!
//! The protocol-digest handshake admits three kinds of peer: one that declared
//! OUR digest, one that declared a DIFFERENT one, and one that declared nothing
//! because its binary predates the handshake. Admitting the third is what makes
//! the mechanism shippable onto a live chain — every validator running today is
//! in it, and a refusal that fired on them would be worse than the defect.
//!
//! It stops being correct the moment a rule actually changes. Above the first
//! remediation activation, an undeclared peer is indistinguishable from one
//! still running the unremediated binary: it may propose blocks this node must
//! reject, and move this node's fork choice before it does.
//!
//! So the field is a deadline, and these tests are about the deadline being
//! MET. A value set too late, or left unset while a gate is open, leaves a band
//! of heights in which the guarantee is simply absent — and an operator would
//! find that out at the activation height, on a live chain, rather than here.
//!
//! # Why it is a `ChainParams` gate
//!
//! Because two nodes holding different values partition the network: the one
//! with the lower height refuses peers the other still talks to, and neither
//! can see that as the reason. A value that must be identical across
//! validators, and comparable when it is not, is exactly what `ChainParams` and
//! `activation_heights()` are for — and being folded there, a disagreement
//! about WHEN to enforce is reported by the very digest it configures.

use sumchain_genesis::{ChainParams, Genesis, GenesisError, REMEDIATION_GATES};

fn genesis(params: ChainParams) -> Genesis {
    Genesis::new(
        1,
        1_734_624_000_000,
        vec![
            "GW1pJKzqDmmHczMGz5g7CV51RgDuR6kKw76yZ1cVbEv8".to_string(),
            "7jUZxm5rJ5PazGYkrtJ4sUJj7ztib2VHEoM2Yc4Liydy".to_string(),
        ],
        [("8zZ1pfbpUcAmoByWKYgJgiFZWpmhWQKJ4".to_string(), 500u128)]
            .into_iter()
            .collect(),
        params,
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// The default, which is what every deployed genesis resolves to.
// ─────────────────────────────────────────────────────────────────────────────

/// Unset by default, and a default genesis validates.
///
/// This is the whole deployability claim on the genesis side. `None` means
/// phase one forever — a peer that declares nothing is admitted at every
/// height — which is byte-for-byte how a node behaved before this field
/// existed. It is also the only value consistent with twenty dormant gates.
#[test]
fn the_enforcement_height_is_unset_by_default_and_a_default_genesis_validates() {
    let p = ChainParams::default();
    assert_eq!(
        p.peer_protocol_declaration_required_from_height, None,
        "the default must be phase one: enforcement is a coordinated decision, \
         and a default is not one"
    );
    assert_eq!(
        p.remediation_activation_floor(),
        None,
        "with every remediation gate dormant there is no deadline to meet"
    );
    genesis(p).validate().expect("a default genesis must load");
}

/// A `genesis.json` written before the field existed still parses, and reads
/// dormant.
///
/// `#[serde(default)]` is what makes this a non-event for every file already
/// distributed. Without it, every existing genesis would fail to load — and it
/// would fail at node start, on the operator's machine, not here.
#[test]
fn a_genesis_written_before_this_field_still_parses_and_still_validates() {
    let full = serde_json::to_value(ChainParams::default()).expect("serialise");
    let mut stripped = full.clone();
    let obj = stripped.as_object_mut().expect("params is an object");
    assert!(
        obj.remove("peer_protocol_declaration_required_from_height")
            .is_some(),
        "the field must be serialised, or an operator cannot set it"
    );

    let back: ChainParams = serde_json::from_value(stripped).expect(
        "a genesis with no peer_protocol_declaration_required_from_height must \
         still parse — checked here rather than discovered at a validator's \
         node start",
    );
    assert_eq!(back.peer_protocol_declaration_required_from_height, None);
    genesis(back)
        .validate()
        .expect("and it must still load, unchanged in behaviour");
}

// ─────────────────────────────────────────────────────────────────────────────
// The deadline.
// ─────────────────────────────────────────────────────────────────────────────

/// The floor is the EARLIEST open remediation gate, not the latest and not the
/// first declared.
#[test]
fn the_floor_is_the_earliest_open_remediation_gate() {
    let p = ChainParams {
        // Declared out of order on purpose: the answer is 300, and a `find`
        // that returned the first non-`None` in declaration order would say
        // 900 here.
        nft_receipt_failure_enabled_from_height: Some(900),
        subsystem_no_op_receipt_enabled_from_height: Some(300),
        tax_authorization_enabled_from_height: Some(700),
        peer_protocol_declaration_required_from_height: Some(300),
        ..ChainParams::default()
    };
    assert_eq!(
        p.remediation_activation_floor(),
        Some(("subsystem_no_op_receipt_enabled_from_height", 300))
    );
    genesis(p)
        .validate()
        .expect("enforcement exactly at the floor is legal");
}

/// Every one of the twenty gates counts toward the deadline, one at a time.
///
/// Not one representative gate: a floor computed from a list that had lost an
/// entry would pass a single-gate test and silently skip the gate it lost.
#[test]
fn each_of_the_twenty_gates_sets_the_deadline_on_its_own() {
    for gate in REMEDIATION_GATES {
        let mut json = serde_json::to_value(ChainParams::default()).expect("serialise");
        json.as_object_mut()
            .expect("object")
            .insert((*gate).to_string(), serde_json::json!(500));
        let mut p: ChainParams = serde_json::from_value(json).expect("parse");

        assert_eq!(
            p.remediation_activation_floor(),
            Some((*gate, 500)),
            "{gate} must set the enforcement deadline by itself"
        );

        // One gate in the list carries a SECOND load ordering of its own:
        // `ChainParams::validate` refuses
        // `healthcare_consent_subject_signature_enabled_from_height` unless
        // `healthcare_authorization_enabled_from_height` is at or below it,
        // because `SupersedeConsent` is gated by the second and mints the
        // record the first refuses. Opening the prerequisite at the SAME height
        // keeps the deadline at 500 and moves only WHICH gate reports it: ties
        // in `remediation_activation_floor` go to the earlier entry in
        // `REMEDIATION_GATES`, and authorization precedes the grant gate there.
        // Stated rather than skipped -- a loop that quietly excluded a gate
        // would stop proving the deadline for it.
        let mut floor_gate: &str = gate;
        if *gate == "healthcare_consent_subject_signature_enabled_from_height" {
            p.healthcare_authorization_enabled_from_height = Some(500);
            floor_gate = "healthcare_authorization_enabled_from_height";
        }

        // Unset enforcement: refused.
        match genesis(p.clone()).validate() {
            Err(GenesisError::RemediationGateWithoutPeerProtocolEnforcement {
                gate: g,
                height,
            }) => {
                assert_eq!(g, floor_gate);
                assert_eq!(height, 500);
            }
            other => {
                panic!("{gate} open with no enforcement height must be refused, got {other:?}")
            }
        }

        // Enforcement at the gate: accepted.
        let ok = ChainParams {
            peer_protocol_declaration_required_from_height: Some(500),
            ..p.clone()
        };
        genesis(ok)
            .validate()
            .unwrap_or_else(|e| panic!("{gate} with enforcement at 500 must load: {e}"));

        // Enforcement one block after the gate: refused.
        let late = ChainParams {
            peer_protocol_declaration_required_from_height: Some(501),
            ..p
        };
        match genesis(late).validate() {
            Err(GenesisError::PeerProtocolEnforcementAfterRemediationGate {
                enforcement,
                gate: g,
                height,
            }) => {
                assert_eq!((enforcement, g, height), (501, floor_gate, 500));
            }
            other => {
                panic!("{gate} with enforcement one block late must be refused, got {other:?}")
            }
        }
    }
}

/// Enforcement BELOW the floor is legal, and enforcement from genesis is too.
///
/// The constraint is "at or below", not "equal to": an operator who wants the
/// declaration required earlier than the rules diverge is making the network
/// stricter, which is never the failure this check exists to catch.
#[test]
fn enforcement_earlier_than_the_deadline_is_legal() {
    for enforcement in [0u64, 1, 499, 500] {
        let p = ChainParams {
            legal_authorization_enabled_from_height: Some(500),
            peer_protocol_declaration_required_from_height: Some(enforcement),
            ..ChainParams::default()
        };
        genesis(p)
            .validate()
            .unwrap_or_else(|e| panic!("enforcement at {enforcement} must load: {e}"));
    }
}

/// An enforcement height with NO gate open is legal.
///
/// Setting it early is how an operator prepares for an activation: the height
/// goes into the genesis one release before the gate does, so the network is
/// already refusing undeclared peers when the gate lands.
#[test]
fn an_enforcement_height_with_no_gate_open_is_legal() {
    let p = ChainParams {
        peer_protocol_declaration_required_from_height: Some(42),
        ..ChainParams::default()
    };
    assert_eq!(p.remediation_activation_floor(), None);
    genesis(p).validate().expect("preparing early must load");
}

// ─────────────────────────────────────────────────────────────────────────────
// The field is comparable, which is the reason it is here and not in the binary.
// ─────────────────────────────────────────────────────────────────────────────

/// The enforcement height moves the activation digest.
///
/// Two validators holding different values partition the network. Folding the
/// field means that difference is reported by the digest before the height
/// arrives, rather than discovered as an unexplained loss of peers after it.
#[test]
fn the_enforcement_height_is_folded_into_the_activation_digest() {
    let base = genesis(ChainParams::default()).activation_digest().unwrap();

    let at_zero = genesis(ChainParams {
        peer_protocol_declaration_required_from_height: Some(0),
        ..ChainParams::default()
    })
    .activation_digest()
    .unwrap();
    assert_ne!(
        base, at_zero,
        "`None` and `Some(0)` are opposite configurations — phase one forever \
         against enforcement from genesis — and must not digest alike"
    );

    let at_one = genesis(ChainParams {
        peer_protocol_declaration_required_from_height: Some(1),
        ..ChainParams::default()
    })
    .activation_digest()
    .unwrap();
    assert_ne!(
        at_zero, at_one,
        "a mistyped digit in this height is exactly the disagreement the digest \
         exists to surface"
    );
}

/// The field is covered by `activation_heights`, by name.
///
/// `remediation_activation_floor` looks its gates up through that list, so a
/// name present in one place and not the other is a floor that silently skips a
/// gate. The generic exhaustiveness test in `activation_digest.rs` covers the
/// direction where a field is declared and not folded; this pins the specific
/// name the enforcement logic depends on.
#[test]
fn the_enforcement_height_and_every_remediation_gate_are_named_in_activation_heights() {
    let names: Vec<&str> = ChainParams::default()
        .activation_heights()
        .into_iter()
        .map(|(n, _)| n)
        .collect();

    assert!(
        names.contains(&"peer_protocol_declaration_required_from_height"),
        "the enforcement height must be folded, or two validators can disagree \
         about when enforcement begins with nothing to compare"
    );
    for gate in REMEDIATION_GATES {
        assert!(
            names.contains(gate),
            "{gate} is named in REMEDIATION_GATES and not in activation_heights; \
             remediation_activation_floor would panic rather than skip it, but \
             the drift is the bug"
        );
    }
    assert_eq!(
        REMEDIATION_GATES.len(),
        42,
        "forty-two remediation gates; a merge that spliced two entries together \
         leaves a list that still compiles and is one short"
    );
    let distinct: std::collections::BTreeSet<&&str> = REMEDIATION_GATES.iter().collect();
    assert_eq!(distinct.len(), 42, "and forty-two DISTINCT ones");
}
