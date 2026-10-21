//! Genesis validation enforces the validator construction rules (VS-5 and
//! VS-6(a), ratified 2026-10-21):
//! * the count is 1 to 29,127, checked before any key is looked at;
//! * each key, in declared order, is base58 for 32 bytes, decodes to a curve
//!   point, is canonically encoded and is not of small order;
//! * no key repeats.
//!
//! Every tracked genesis with real keys is still accepted. The byte identity of
//! their genesis blocks, ConsensusConfig encodings and digests is pinned in
//! `crates/consensus/tests/genesis_strict_fields_identity.rs`.

use std::path::{Path, PathBuf};

use sumchain_crypto::{check_validator_key, ValidatorKeyRule};
use sumchain_genesis::{Genesis, GenesisError, MAX_GENESIS_VALIDATORS};
use sumchain_primitives::proposer::{check_validator_set, ProposerSelectionError};

const VECTORS: &str = include_str!("../../crypto/tests/vectors/validator_key_rules.tsv");

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// `genesis/local_genesis.json`: three real validators.
fn base() -> Genesis {
    Genesis::from_file(root().join("genesis/local_genesis.json")).unwrap()
}

fn with_validators(validators: Vec<String>) -> Genesis {
    let mut g = base();
    g.validators = validators;
    g
}

fn b58(bytes: &[u8; 32]) -> String {
    bs58::encode(bytes).into_string()
}

fn vectors() -> Vec<(&'static str, [u8; 32], &'static str)> {
    VECTORS
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .map(|l| {
            let cols: Vec<&str> = l.splitn(3, '\t').collect();
            let bytes: [u8; 32] = hex::decode(cols[1]).unwrap().try_into().unwrap();
            (cols[0], bytes, cols[2])
        })
        .collect()
}

#[test]
fn each_invalid_key_class_is_refused_naming_index_key_and_rule() {
    let real = base().validators;
    let mut refused = 0;
    for (verdict, bytes, what) in vectors() {
        let key = b58(&bytes);
        let g = with_validators(vec![real[0].clone(), key.clone(), real[2].clone()]);
        let rule = match verdict {
            "ok" => {
                g.validate().unwrap_or_else(|e| panic!("{what}: {e}"));
                continue;
            }
            "undecodable" => ValidatorKeyRule::Undecodable,
            "non_canonical" => ValidatorKeyRule::NonCanonical,
            "small_order" => ValidatorKeyRule::SmallOrder,
            other => panic!("unknown verdict {other:?}"),
        };
        let err = g.validate().unwrap_err();
        match &err {
            GenesisError::InvalidValidatorKey {
                index: 1,
                key: k,
                rule: r,
            } => {
                assert_eq!((k, *r), (&key, rule), "{what}");
            }
            other => panic!("{what}: {other}"),
        }
        let msg = err.to_string();
        assert!(msg.contains("validator[1]") && msg.contains(&key), "{msg}");
        assert!(msg.ends_with(&rule.to_string()), "{msg}");
        // The same file read through `from_json` is refused the same way.
        let json = serde_json::to_string(&g).unwrap();
        assert!(matches!(
            Genesis::from_json(&json),
            Err(GenesisError::InvalidValidatorKey { index: 1, .. })
        ));
        refused += 1;
    }
    assert_eq!(refused, 18);
}

#[test]
fn the_count_is_checked_first_and_bounded_by_29127() {
    assert_eq!(MAX_GENESIS_VALIDATORS, 29_127);
    assert!(matches!(
        with_validators(Vec::new()).validate(),
        Err(GenesisError::NoValidators)
    ));
    // One over the bound is refused before any key is parsed: these are not
    // keys at all.
    let err = with_validators(vec!["not a key".into(); MAX_GENESIS_VALIDATORS + 1])
        .validate()
        .unwrap_err();
    assert!(
        matches!(
            err,
            GenesisError::TooManyValidators {
                n: 29_128,
                max: 29_127
            }
        ),
        "{err}"
    );
    assert!(err.to_string().contains("29128") && err.to_string().contains("29127"));
    // At the bound the count passes, and the first key is what fails.
    let err = with_validators(vec!["not a key".into(); MAX_GENESIS_VALIDATORS])
        .validate()
        .unwrap_err();
    assert!(
        matches!(&err, GenesisError::InvalidValidator(m) if m.starts_with("validator[0]")),
        "{err}"
    );
    // One validator is enough.
    with_validators(vec![base().validators[0].clone()])
        .validate()
        .unwrap();
}

#[test]
fn a_key_that_is_not_base58_for_32_bytes_is_refused_as_before() {
    let real = base().validators;
    for bad in [
        "0OIl".to_string(),                    // not base58
        b58(&[7; 32])[..20].to_string(),       // too short
        bs58::encode([5u8; 33]).into_string(), // 33 bytes
        String::new(),
    ] {
        let g = with_validators(vec![real[0].clone(), bad.clone()]);
        let err = g.validate().unwrap_err();
        assert_eq!(
            err.to_string(),
            format!("Invalid validator public key: validator[1]: {bad}")
        );
    }
}

#[test]
fn a_repeated_key_is_refused_with_the_proposer_rules_positions() {
    let r = base().validators;
    for layout in [
        vec![0usize, 0],
        vec![0, 1, 0],
        vec![0, 1, 2, 1],
        vec![2, 0, 1, 0, 2],
    ] {
        let list: Vec<String> = layout.iter().map(|&i| r[i].clone()).collect();
        let keys: Vec<[u8; 32]> = list
            .iter()
            .map(|k| bs58::decode(k).into_vec().unwrap().try_into().unwrap())
            .collect();
        let expected = check_validator_set(&keys).unwrap_err();
        assert!(matches!(
            expected,
            ProposerSelectionError::DuplicateValidator { .. }
        ));
        match with_validators(list).validate() {
            Err(GenesisError::InvalidValidatorSet(got)) => assert_eq!(got, expected, "{layout:?}"),
            other => panic!("{layout:?}: {other:?}"),
        }
    }
}

#[test]
fn the_first_failure_in_declared_order_is_reported() {
    let r = base().validators;
    let small = b58(&[0u8; 32]);
    let noncanonical_small = b58(&{
        let mut y = [0xffu8; 32];
        y[0] = 0xed;
        y[31] = 0x7f;
        y
    });
    // A bad key after a repeat: the repeat (index 1) is reported.
    let err = with_validators(vec![r[0].clone(), r[0].clone(), small.clone()])
        .validate()
        .unwrap_err();
    assert!(matches!(err, GenesisError::InvalidValidatorSet(_)), "{err}");
    // A repeated bad key: the key rule at its first index.
    let err = with_validators(vec![small.clone(), r[0].clone(), small])
        .validate()
        .unwrap_err();
    assert!(
        matches!(
            err,
            GenesisError::InvalidValidatorKey {
                index: 0,
                rule: ValidatorKeyRule::SmallOrder,
                ..
            }
        ),
        "{err}"
    );
    // y = p encodes a small-order point non-canonically: non-canonical first.
    let err = with_validators(vec![noncanonical_small])
        .validate()
        .unwrap_err();
    assert!(
        matches!(
            err,
            GenesisError::InvalidValidatorKey {
                index: 0,
                rule: ValidatorKeyRule::NonCanonical,
                ..
            }
        ),
        "{err}"
    );
}

/// Every tracked genesis that holds real keys is still accepted, and every key
/// in it passes the rules; the placeholder templates are refused as before.
#[test]
fn tracked_geneses_are_still_accepted_and_templates_still_refused() {
    for f in [
        "genesis.json",
        "genesis/local_genesis.json",
        "docs/operations/evidence/stage1-local-2026-09-24/genesis-1v.json",
        "docs/operations/evidence/stage1-local-2026-09-24/genesis-2v.json",
        "docs/operations/evidence/stage1-local-2026-09-24/genesis-A.json",
        "docs/operations/evidence/stage1-local-2026-09-24/genesis-B.json",
    ] {
        let g = Genesis::from_file(root().join(f)).unwrap_or_else(|e| panic!("{f}: {e}"));
        for k in g.validator_pubkeys().unwrap() {
            assert_eq!(check_validator_key(&k), Ok(()), "{f}");
        }
    }
    for f in [
        "genesis/mainnet_genesis.json",
        "genesis/testnet_genesis.json",
        "genesis/snip-mirror-genesis.template.json",
    ] {
        let err = Genesis::from_file(root().join(f)).unwrap_err().to_string();
        assert!(
            err.starts_with("Invalid validator public key"),
            "{f}: {err}"
        );
    }
}
