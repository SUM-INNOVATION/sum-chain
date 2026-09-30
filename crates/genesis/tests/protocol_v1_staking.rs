//! Protocol v1 staking and validator-set rules at the genesis boundary (#267).
//!
//! * The generated default is static membership with round-robin proposers.
//! * `stake_weighted_selection = true` and any `epoch_length != 0` are refused
//!   by the loader, never coerced into round robin or static membership.
//! * A validator listed twice is refused.
//! * Every genesis shipped in this repository still loads.
//!
//! Keys are synthetic.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use sumchain_crypto::KeyPair;
use sumchain_genesis::{ChainParams, Genesis, GenesisError};
use sumchain_primitives::staking::StakingV1Refusal;
use sumchain_primitives::StakingParams;

fn validators(n: u8) -> Vec<String> {
    (1..=n)
        .map(|i| KeyPair::from_bytes([i; 32]).public_key().to_base58())
        .collect()
}

fn genesis_json(staking: Option<StakingParams>) -> String {
    let params = ChainParams {
        staking,
        ..ChainParams::default()
    };
    Genesis::new(7, 0, validators(2), HashMap::new(), params)
        .to_json()
        .unwrap()
}

#[test]
fn the_generated_default_is_static_and_round_robin() {
    let d = StakingParams::default();
    assert!(!d.stake_weighted_selection);
    assert_eq!(d.epoch_length, 0);
    assert_eq!(d.check_protocol_v1(), Ok(()));
    let params = ChainParams::default();
    assert_eq!(params.staking.as_ref(), Some(&d));
    params.validate().expect("the default parameters are valid");
    Genesis::from_json(&genesis_json(Some(StakingParams::default())))
        .expect("a genesis written from the defaults loads");
}

#[test]
fn stake_weighted_selection_is_refused_at_load() {
    let json = genesis_json(Some(StakingParams {
        stake_weighted_selection: true,
        ..StakingParams::default()
    }));
    match Genesis::from_json(&json) {
        Err(GenesisError::StakingProtocolV1(StakingV1Refusal::StakeWeightedSelection)) => {}
        other => panic!("expected the stake-weighted refusal, got {other:?}"),
    }
    let err = Genesis::from_json(&json).unwrap_err().to_string();
    assert!(err.contains("unavailable in protocol v1"), "{err}");
    assert!(
        err.contains("does not fall back to round robin silently"),
        "{err}"
    );
}

#[test]
fn dynamic_epochs_are_refused_at_load() {
    for epoch_length in [1u64, 14_400] {
        let json = genesis_json(Some(StakingParams {
            epoch_length,
            ..StakingParams::default()
        }));
        match Genesis::from_json(&json) {
            Err(GenesisError::StakingProtocolV1(StakingV1Refusal::DynamicEpochs {
                epoch_length: got,
            })) => assert_eq!(got, epoch_length),
            other => panic!("expected the dynamic-epoch refusal, got {other:?}"),
        }
        let err = Genesis::from_json(&json).unwrap_err().to_string();
        assert!(err.contains("#266"), "{err}");
        assert!(err.contains("does not disable epochs silently"), "{err}");
    }
}

/// No fallback: a `true` in the file stays `true` all the way to the check, so
/// it is refused rather than read as `false`; and the field has no serde default,
/// so a staking section that omits it is a parse error, not an implicit value.
#[test]
fn nothing_turns_an_unsafe_value_into_a_safe_one() {
    let json = genesis_json(Some(StakingParams {
        stake_weighted_selection: true,
        ..StakingParams::default()
    }));
    let raw: Genesis = serde_json::from_str(&json).unwrap();
    assert!(
        raw.params
            .staking
            .as_ref()
            .unwrap()
            .stake_weighted_selection
    );
    assert!(raw.validate().is_err());

    let mut value: serde_json::Value =
        serde_json::from_str(&genesis_json(Some(StakingParams::default()))).unwrap();
    value["params"]["staking"]
        .as_object_mut()
        .unwrap()
        .remove("stake_weighted_selection");
    let err = Genesis::from_json(&value.to_string()).unwrap_err();
    assert!(matches!(err, GenesisError::Json(_)), "{err:?}");
}

#[test]
fn a_static_staking_section_or_none_loads() {
    Genesis::from_json(&genesis_json(None)).expect("no staking section");
    Genesis::from_json(&genesis_json(Some(StakingParams {
        epoch_length: 0,
        stake_weighted_selection: false,
        ..StakingParams::default()
    })))
    .expect("an explicitly static staking section");
}

#[test]
fn a_validator_listed_twice_is_refused() {
    let mut vs = validators(3);
    vs.push(vs[1].clone());
    let json = Genesis::new(7, 0, vs, HashMap::new(), ChainParams::default())
        .to_json()
        .unwrap();
    let err = Genesis::from_json(&json).unwrap_err();
    assert!(
        matches!(err, GenesisError::InvalidValidatorSet(_)),
        "{err:?}"
    );
    assert!(err.to_string().contains("positions 1 and 3"), "{err}");
}

#[test]
fn the_genesis_proposer_is_round_robin_height_zero() {
    let g = Genesis::from_json(&genesis_json(None)).unwrap();
    assert_eq!(
        g.genesis_proposer().unwrap(),
        g.validator_pubkeys().unwrap()[0]
    );
    let empty = Genesis::new(7, 0, Vec::new(), HashMap::new(), ChainParams::default());
    assert!(
        empty.genesis_proposer().is_err(),
        "an empty set is an error, not a panic"
    );
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Every genesis shipped in the repository is static and loads as it did:
/// none has a staking section, and every one whose validator keys are real keys
/// (not a template placeholder such as `TESTNET_VALIDATOR1_PUBKEY`, which never
/// loaded) still loads under the new rules.
#[test]
fn every_shipped_genesis_is_static_and_still_loads() {
    let root = repo_root();
    let mut files = vec![root.join("genesis.json")];
    for dir in [
        "genesis",
        "docs/operations/evidence/stage1-local-2026-09-24",
    ] {
        for entry in std::fs::read_dir(root.join(dir)).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            if name.ends_with(".json") && name.contains("genesis") {
                files.push(path);
            }
        }
    }
    assert!(files.len() >= 5, "shipped genesis files not found");
    let mut loaded = 0;
    for path in files {
        let text = std::fs::read_to_string(&path).unwrap();
        let raw: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert!(
            raw["params"].get("staking").is_none(),
            "{} has a staking section",
            path.display()
        );
        let keys_are_real = raw["validators"]
            .as_array()
            .unwrap()
            .iter()
            .all(|v| sumchain_crypto::PublicKey::from_base58(v.as_str().unwrap()).is_ok());
        if keys_are_real {
            Genesis::from_file(&path)
                .unwrap_or_else(|e| panic!("{} no longer loads: {e}", path.display()));
            loaded += 1;
        }
    }
    assert!(
        loaded >= 4,
        "expected the real-key genesis files to be exercised"
    );
}
