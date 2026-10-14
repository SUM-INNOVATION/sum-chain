//! The #126 validator-topology guard on compute-pool enablement, at the
//! genesis loader.
//!
//! * The set counted is the genesis validator list: protocol v1 keeps
//!   membership static, so that list is the whole live set at every height.
//! * `compute_pool_enabled_from_height` over 2, 3 or 4 validators is refused
//!   by the guard, which reports the count and the bounds 4 / 5 / 7 and says
//!   it does not evaluate the maintenance/operational minimum (7, #248).
//! * Over 5 or more the guard passes and the existing refusals follow,
//!   unchanged: the pool gate is still refused (`IncompleteSubsystemActivation`,
//!   or the #129 retention refusal when parameters are declared).
//! * Nothing else moves: a dormant gate loads at any size, the beacon gate is
//!   refused exactly as before, and the protocol v1 staking rules still refuse
//!   first.
//!
//! Keys are synthetic.

use std::collections::HashMap;

use serde_json::{json, Value};
use sumchain_crypto::KeyPair;
use sumchain_genesis::compute_pool_retention_inputs::RetentionActivationError;
use sumchain_genesis::pool_topology::{
    self, BelowProductMinimum, CRYPTOGRAPHIC_MINIMUM, MAINTENANCE_MINIMUM, PRODUCT_MINIMUM,
};
use sumchain_genesis::{ChainParams, Genesis, GenesisError};
use sumchain_primitives::staking::StakingV1Refusal;
use sumchain_primitives::StakingParams;

fn validators(n: u8) -> Vec<String> {
    (1..=n)
        .map(|i| KeyPair::from_bytes([i; 32]).public_key().to_base58())
        .collect()
}

fn genesis(n: u8, params: ChainParams) -> Genesis {
    Genesis::new(7, 0, validators(n), HashMap::new(), params)
}

fn pool_gate(h: u64) -> ChainParams {
    ChainParams {
        compute_pool_enabled_from_height: Some(h),
        ..ChainParams::default()
    }
}

/// Through the JSON loader, as a node reads it.
fn load(g: &Genesis) -> Result<Genesis, GenesisError> {
    Genesis::from_json(&g.to_json().unwrap())
}

/// TEST_ONLY compute-pool values: structurally valid, nothing more.
fn declared_pool_params() -> Value {
    json!({
        "b_offer": 0, "b_commit": 0, "b_check": 0,
        "c_layer": 0, "c_tok": 0, "c_sel": 0, "c_emit": 0,
        "accept_reimb": 0, "commit_verify_reimb": 0, "publish_reimb": 0,
        "observe_reimb": 0, "check_reimb": 0, "settle_reimb": 0, "reassign_reimb": 0,
        "max_work_units": 1, "max_generations": 1, "max_reprovisionable_units": 1,
        "max_attempts_per_unit": 1, "max_reassignments_per_file": 1,
        "k_susp": 0, "w_susp": 0, "s_susp": 0, "n_invite_max": 0,
        "max_retention_files_per_job": 1, "max_retention_updates_per_block": 1,
        "max_reverse_index_entries": 1, "output_availability_blocks": 200,
        "d_avail": 0, "d_ack": 0, "d_final": 0
    })
}

#[test]
fn the_guard_counts_the_genesis_validator_list() {
    for n in [1u8, 2, 4, 5, 7] {
        let g = genesis(n, ChainParams::default());
        let set = g.validator_pubkeys().unwrap();
        assert_eq!(set.len(), n as usize);
        assert_eq!(pool_topology::validator_count(&set), n as usize);
    }
}

#[test]
fn pool_enablement_over_two_three_or_four_validators_is_refused_by_the_guard() {
    for n in [1u8, 2, 3, 4] {
        for h in [0u64, 1, 9_000_000] {
            match load(&genesis(n, pool_gate(h))) {
                Err(GenesisError::PoolActivationTopology(e)) => assert_eq!(
                    e,
                    BelowProductMinimum {
                        validators: n as usize,
                        cryptographic_minimum: CRYPTOGRAPHIC_MINIMUM,
                        product_minimum: PRODUCT_MINIMUM,
                        maintenance_minimum: MAINTENANCE_MINIMUM,
                    },
                    "n = {n}, gate {h}"
                ),
                other => panic!("n = {n}, gate {h}: expected the topology refusal, got {other:?}"),
            }
        }
    }
    let text = load(&genesis(2, pool_gate(0))).unwrap_err().to_string();
    assert_eq!(
        text,
        "compute_pool_enabled_from_height cannot be enabled over 2 validator(s): pool \
         enablement requires at least 5 (DKG-creation bounds: cryptographic minimum 4, product \
         minimum 5). The separate validator maintenance and operational minimum (7, #248) is not \
         evaluated by this check"
    );
}

/// The guard comes first on the activation path. At five or more validators it
/// passes, and the pool gate is still refused by what refused it before: the
/// incomplete-subsystem refusal, or the #129 retention refusal when parameters
/// are declared.
#[test]
fn at_five_or_more_the_existing_refusals_still_apply_after_the_guard() {
    for n in [5u8, 6, 7, 10] {
        match load(&genesis(n, pool_gate(0))) {
            Err(GenesisError::IncompleteSubsystemActivation {
                gate: "compute_pool_enabled_from_height",
            }) => {}
            other => panic!("n = {n}: expected IncompleteSubsystemActivation, got {other:?}"),
        }
    }
    // With parameters declared: guard, then the retention refusal.
    let with_params = |n: u8| {
        let mut params = pool_gate(0);
        params.compute_pool_params = Some(serde_json::from_value(declared_pool_params()).unwrap());
        load(&genesis(n, params))
    };
    assert!(matches!(
        with_params(4),
        Err(GenesisError::PoolActivationTopology(BelowProductMinimum {
            validators: 4,
            ..
        }))
    ));
    assert!(matches!(
        with_params(5),
        Err(GenesisError::ComputePoolActivationRefused(
            RetentionActivationError::InputsUndefined(_)
        ))
    ));
}

/// A dormant pool gate is not checked: any validator count loads, as before.
#[test]
fn a_dormant_pool_gate_is_unaffected_at_any_size() {
    for n in [1u8, 2, 3, 4, 5] {
        load(&genesis(n, ChainParams::default())).unwrap_or_else(|e| panic!("n = {n}: {e}"));
        let declared = ChainParams {
            compute_pool_params: Some(serde_json::from_value(declared_pool_params()).unwrap()),
            ..ChainParams::default()
        };
        load(&genesis(n, declared)).unwrap_or_else(|e| panic!("n = {n}: {e}"));
    }
}

/// The beacon gate keeps its own refusal; the guard is for pool enablement only.
#[test]
fn the_beacon_gate_is_refused_exactly_as_before() {
    for n in [2u8, 4, 5] {
        let params = ChainParams {
            beacon_enabled_from_height: Some(0),
            ..ChainParams::default()
        };
        match load(&genesis(n, params)) {
            Err(GenesisError::IncompleteSubsystemActivation {
                gate: "beacon_enabled_from_height",
            }) => {}
            other => panic!("n = {n}: expected the beacon refusal, got {other:?}"),
        }
    }
}

/// The protocol v1 staking rules run before the guard: they are what make the
/// genesis list the live set. The guard adds no epoch rule of its own.
#[test]
fn protocol_v1_staking_rules_still_refuse_first() {
    for n in [2u8, 5] {
        let mut params = pool_gate(0);
        params.staking = Some(StakingParams {
            epoch_length: 10,
            ..StakingParams::default()
        });
        match load(&genesis(n, params)) {
            Err(GenesisError::StakingProtocolV1(StakingV1Refusal::DynamicEpochs {
                epoch_length: 10,
            })) => {}
            other => panic!("n = {n}: expected the dynamic-epoch refusal, got {other:?}"),
        }
    }
}

/// `ChainParams::validate` alone has no validator set: the pool gate is
/// refused there as before, by the incomplete-subsystem refusal.
#[test]
fn chain_params_alone_refuse_the_pool_gate_as_before() {
    assert!(matches!(
        pool_gate(0).validate(),
        Err(GenesisError::IncompleteSubsystemActivation {
            gate: "compute_pool_enabled_from_height"
        })
    ));
}
