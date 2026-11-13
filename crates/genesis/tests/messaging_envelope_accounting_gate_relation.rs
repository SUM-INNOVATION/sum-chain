//! Genesis admits the sponsored-envelope gate and the messaging accounting
//! gate only together: both unset, or both set to one height. The peer
//! declaration ordering is checked first and applies to each gate as before.

use sumchain_genesis::{ChainParams, Genesis, GenesisError};

const ENVELOPE: &str = "messaging_sponsored_envelope_verification_enabled_from_height";

/// A genesis on chain 7 with the two gates and the peer declaration as given.
fn genesis(envelope: Option<u64>, accounting: Option<u64>, declaration: Option<u64>) -> Genesis {
    let params = ChainParams {
        messaging_sponsored_envelope_verification_enabled_from_height: envelope,
        messaging_fee_nonce_accounting_enabled_from_height: accounting,
        peer_protocol_declaration_required_from_height: declaration,
        ..ChainParams::default()
    };
    Genesis::new(
        7,
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

#[test]
fn both_unset_is_accepted() {
    genesis(None, None, None)
        .validate()
        .expect("the production default loads");
}

#[test]
fn both_at_one_height_is_accepted() {
    for h in [0, 1, 500, u64::MAX] {
        genesis(Some(h), Some(h), Some(h.min(500)))
            .validate()
            .unwrap_or_else(|e| panic!("both at {h}: {e}"));
    }
}

#[test]
fn one_gate_alone_is_refused() {
    for (envelope, accounting) in [(Some(500), None), (None, Some(500))] {
        match genesis(envelope, accounting, Some(500)).validate() {
            Err(GenesisError::MessagingEnvelopeAndAccountingGatesApart {
                envelope: e,
                accounting: a,
            }) => assert_eq!((e, a), (envelope, accounting)),
            other => panic!("{envelope:?}/{accounting:?}: {other:?}"),
        }
    }
}

#[test]
fn two_heights_are_refused_in_either_order() {
    for (envelope, accounting) in [(500, 501), (501, 500), (1, u64::MAX)] {
        match genesis(Some(envelope), Some(accounting), Some(1)).validate() {
            Err(GenesisError::MessagingEnvelopeAndAccountingGatesApart {
                envelope: e,
                accounting: a,
            }) => assert_eq!((e, a), (Some(envelope), Some(accounting))),
            other => panic!("{envelope}/{accounting}: {other:?}"),
        }
    }
}

/// The peer-declaration ordering runs first and still applies: with the
/// gates at one height and no declaration, or a declaration after them, the
/// refusal is the declaration's; with one gate alone and no declaration, it
/// is the declaration's too.
#[test]
fn the_peer_declaration_ordering_still_applies_first() {
    match genesis(Some(500), Some(500), None).validate() {
        Err(GenesisError::RemediationGateWithoutPeerProtocolEnforcement { gate, height }) => {
            assert_eq!((gate, height), (ENVELOPE, 500))
        }
        other => panic!("{other:?}"),
    }
    match genesis(Some(500), Some(500), Some(501)).validate() {
        Err(GenesisError::PeerProtocolEnforcementAfterRemediationGate {
            enforcement,
            gate,
            height,
        }) => assert_eq!((enforcement, gate, height), (501, ENVELOPE, 500)),
        other => panic!("{other:?}"),
    }
    match genesis(None, Some(500), None).validate() {
        Err(GenesisError::RemediationGateWithoutPeerProtocolEnforcement { height, .. }) => {
            assert_eq!(height, 500)
        }
        other => panic!("{other:?}"),
    }
}
