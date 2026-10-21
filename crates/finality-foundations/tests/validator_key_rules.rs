//! The validator-set construction rules here agree, key by key, with the copy
//! genesis validation uses (`sumchain_crypto::check_validator_key`, VS-5,
//! ratified 2026-10-21). Both are checked against the same vector file; this
//! crate stays free of workspace dependencies, so the file is the meeting
//! point.

use ed25519_dalek::SigningKey;
use sumchain_finality_foundations::vote::{AuthenticatedValidatorSet, ValidatorSetError};

const VECTORS: &str = include_str!("../../crypto/tests/vectors/validator_key_rules.tsv");

#[test]
fn the_set_rules_give_every_shared_vector_its_verdict() {
    let mut n = 0;
    for line in VECTORS.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let cols: Vec<&str> = line.splitn(3, '\t').collect();
        let bytes: [u8; 32] = hex::decode(cols[1]).unwrap().try_into().unwrap();
        // A valid key put first, so the vector is index 1 and the set is
        // otherwise acceptable.
        let valid = SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes();
        let got = AuthenticatedValidatorSet::from_keys(&[valid, bytes]).map(|_| ());
        let want = match cols[0] {
            "ok" => Ok(()),
            "undecodable" => Err(ValidatorSetError::Undecodable { index: 1 }),
            "non_canonical" => Err(ValidatorSetError::NonCanonical { index: 1 }),
            "small_order" => Err(ValidatorSetError::SmallOrder { index: 1 }),
            other => panic!("unknown verdict {other:?}"),
        };
        assert_eq!(got, want, "{}", cols[2]);
        n += 1;
    }
    assert_eq!(n, 22, "the vector file changed size");
}
