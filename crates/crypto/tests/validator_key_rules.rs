//! The per-key validator construction rules (VS-5, ratified 2026-10-21):
//! `check_validator_key` against the shared vectors, which the dormant
//! finality foundations and genesis validation are checked against too.

use curve25519_dalek::edwards::CompressedEdwardsY;
use sumchain_crypto::{check_validator_key, KeyPair, ValidatorKeyRule};

const VECTORS: &str = include_str!("vectors/validator_key_rules.tsv");

fn vectors() -> Vec<(Result<(), ValidatorKeyRule>, [u8; 32], &'static str)> {
    VECTORS
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .map(|l| {
            let cols: Vec<&str> = l.splitn(3, '\t').collect();
            let verdict = match cols[0] {
                "ok" => Ok(()),
                "undecodable" => Err(ValidatorKeyRule::Undecodable),
                "non_canonical" => Err(ValidatorKeyRule::NonCanonical),
                "small_order" => Err(ValidatorKeyRule::SmallOrder),
                other => panic!("unknown verdict {other:?}"),
            };
            let bytes: [u8; 32] = hex::decode(cols[1]).unwrap().try_into().unwrap();
            (verdict, bytes, cols[2])
        })
        .collect()
}

#[test]
fn every_vector_gets_its_verdict() {
    let v = vectors();
    assert_eq!(v.len(), 22, "the vector file changed size");
    for rule in [
        Ok(()),
        Err(ValidatorKeyRule::Undecodable),
        Err(ValidatorKeyRule::NonCanonical),
        Err(ValidatorKeyRule::SmallOrder),
    ] {
        assert!(
            v.iter().any(|(r, _, _)| *r == rule),
            "no vector for {rule:?}"
        );
    }
    for (want, bytes, what) in v {
        assert_eq!(check_validator_key(&bytes), want, "{what}");
    }
}

/// The verdicts are not just this implementation's: each one is what the
/// curve arithmetic says, checked directly with curve25519-dalek.
#[test]
fn every_verdict_matches_the_curve_arithmetic() {
    for (want, bytes, what) in vectors() {
        let oracle = match CompressedEdwardsY(bytes).decompress() {
            None => Err(ValidatorKeyRule::Undecodable),
            Some(p) if p.compress().to_bytes() != bytes => Err(ValidatorKeyRule::NonCanonical),
            Some(p) if p.is_small_order() => Err(ValidatorKeyRule::SmallOrder),
            Some(_) => Ok(()),
        };
        assert_eq!(oracle, want, "{what}");
    }
    let base = curve25519_dalek::constants::ED25519_BASEPOINT_COMPRESSED.to_bytes();
    assert_eq!(
        hex::encode(base),
        "5866666666666666666666666666666666666666666666666666666666666666"
    );
}

#[test]
fn generated_keys_always_pass() {
    for i in 0..=255u8 {
        let key = KeyPair::from_bytes([i; 32]);
        assert_eq!(
            check_validator_key(key.public_key().as_bytes()),
            Ok(()),
            "seed {i}"
        );
    }
}

#[test]
fn the_rule_names_are_stable() {
    assert_eq!(
        ValidatorKeyRule::Undecodable.to_string(),
        "does not decode to an Ed25519 curve point"
    );
    assert_eq!(
        ValidatorKeyRule::NonCanonical.to_string(),
        "is not the canonical encoding of its curve point"
    );
    assert_eq!(
        ValidatorKeyRule::SmallOrder.to_string(),
        "is a small-order point"
    );
}
