//! The PROPOSED, UNRATIFIED validator-set commitment (draft §2):
//! `BLAKE3-256(D_VALSET ‖ n:u16 LE ‖ key_0 ‖ … ‖ key_{n-1})`, keys in
//! authenticated order. Every vector here is SYNTHETIC (test seeds
//! `[0x01;32]`..`[0x04;32]`) and reproduces `docs/proposals/g2-byte-review/`.

use ed25519_dalek::{SigningKey, VerifyingKey};
use serde_json::Value;
use sumchain_finality_foundations::vote::{
    validator_set_commitment, validator_set_preimage, validator_set_preimage_len,
    AuthenticatedValidatorSet, ValidatorSetError, D_VALSET, MAX_VALIDATORS,
};
use sumchain_finality_foundations::Digest;

const BYTE_REVIEW: &str = include_str!("../../../docs/proposals/g2-byte-review/vectors.json");
const VOTE_VECTORS: &str = include_str!("vectors/finality_vote_v1.json");

fn review_vector(name: &str) -> Vec<u8> {
    let v: Value = serde_json::from_str(BYTE_REVIEW).unwrap();
    let hex = v["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["name"] == name)
        .unwrap_or_else(|| panic!("vector {name}"))["hex"]
        .as_str()
        .unwrap()
        .to_string();
    hex::decode(hex).unwrap()
}

fn digest(bytes: &[u8]) -> Digest {
    bytes.try_into().expect("32 bytes")
}

/// Public key of the test seed `[i;32]`.
fn seed_key(i: u8) -> [u8; 32] {
    SigningKey::from_bytes(&[i; 32]).verifying_key().to_bytes()
}

fn seed_keys(n: u8) -> Vec<[u8; 32]> {
    (1..=n).map(seed_key).collect()
}

/// `n` distinct valid keys from 32-byte seeds `[i as LE, 0…]`.
fn many_keys(n: usize) -> Vec<[u8; 32]> {
    (0..n)
        .map(|i| {
            let mut seed = [0u8; 32];
            seed[..8].copy_from_slice(&(i as u64 + 1).to_le_bytes());
            seed[31] = 0xa5;
            SigningKey::from_bytes(&seed).verifying_key().to_bytes()
        })
        .collect()
}

// ------------------------------------------------------------- vectors ----

#[test]
fn domain_and_sizes_are_as_drafted() {
    assert_eq!(D_VALSET, b"SUMCHAIN/VALSET/v1\0");
    assert_eq!(
        hex::encode(D_VALSET),
        "53554d434841494e2f56414c5345542f763100"
    );
    assert_eq!(D_VALSET.len(), 19);
    assert_eq!(D_VALSET.iter().filter(|&&b| b == 0).count(), 1);
    assert_eq!(*D_VALSET.last().unwrap(), 0, "NUL-terminated");
    assert_eq!(validator_set_preimage_len(1), 53);
    assert_eq!(validator_set_preimage_len(2), 85);
    assert_eq!(validator_set_preimage_len(4), 149);
    assert_eq!(validator_set_preimage_len(MAX_VALIDATORS), 2_097_141);
}

#[test]
fn reproduces_the_byte_review_vectors() {
    let keys = seed_keys(4);
    for (i, key) in keys.iter().enumerate() {
        assert_eq!(key.to_vec(), review_vector(&format!("pubkey[{i}]")));
    }
    let preimage = validator_set_preimage(&keys).unwrap();
    assert_eq!(preimage, review_vector("valset n=4"));
    assert_eq!(preimage.len(), 149);
    assert_eq!(
        validator_set_commitment(&keys).unwrap().to_vec(),
        review_vector("valset n=4 commitment")
    );
    assert_eq!(
        validator_set_commitment(&keys[..2]).unwrap().to_vec(),
        review_vector("valset n=2 commitment")
    );
}

#[test]
fn reproduces_the_ratified_vote_vectors_commitment() {
    let v: Value = serde_json::from_str(VOTE_VECTORS).unwrap();
    let named = hex::decode(v["validator_set_commitment"].as_str().unwrap()).unwrap();
    assert_eq!(
        validator_set_commitment(&seed_keys(4)).unwrap().to_vec(),
        named
    );
}

#[test]
fn the_commitment_is_blake3_of_the_preimage() {
    for keys in [seed_keys(1), seed_keys(3), many_keys(257)] {
        let preimage = validator_set_preimage(&keys).unwrap();
        let n = u16::try_from(keys.len()).unwrap();
        assert_eq!(preimage.len(), validator_set_preimage_len(n));
        assert_eq!(&preimage[..19], D_VALSET);
        assert_eq!(&preimage[19..21], &n.to_le_bytes(), "n is little-endian");
        for (i, key) in keys.iter().enumerate() {
            assert_eq!(&preimage[21 + 32 * i..53 + 32 * i], key);
        }
        assert_eq!(
            validator_set_commitment(&keys).unwrap(),
            *blake3::hash(&preimage).as_bytes()
        );
    }
}

#[test]
fn order_and_domain_matter() {
    let keys = seed_keys(4);
    let base = validator_set_commitment(&keys).unwrap();
    let mut swapped = keys.clone();
    swapped.swap(1, 2);
    assert_ne!(validator_set_commitment(&swapped).unwrap(), base);
    let mut rotated = keys.clone();
    rotated.rotate_left(1);
    assert_ne!(validator_set_commitment(&rotated).unwrap(), base);
    // Neither the bare keys nor the keys under another domain give the same digest.
    let bare: Vec<u8> = keys.iter().flatten().copied().collect();
    assert_ne!(*blake3::hash(&bare).as_bytes(), base);
    let mut other = b"SUMCHAIN/VALSET/v2\0".to_vec();
    other.extend_from_slice(&4u16.to_le_bytes());
    other.extend_from_slice(&bare);
    assert_ne!(*blake3::hash(&other).as_bytes(), base);
    // A prefix of the set is a different set.
    assert_ne!(validator_set_commitment(&keys[..3]).unwrap(), base);
}

// --------------------------------------------------------- constructors ----

#[test]
fn from_keys_names_the_set_by_its_derived_commitment() {
    let keys = seed_keys(4);
    let set = AuthenticatedValidatorSet::from_keys(&keys).unwrap();
    assert_eq!(*set.commitment(), validator_set_commitment(&keys).unwrap());
    assert_eq!(set.len(), 4);
    for (i, key) in keys.iter().enumerate() {
        assert_eq!(
            set.key(u16::try_from(i).unwrap()).unwrap(),
            &VerifyingKey::from_bytes(key).unwrap()
        );
    }
    // The same set through the caller-commitment constructor is equal.
    assert_eq!(
        AuthenticatedValidatorSet::new(*set.commitment(), &keys).unwrap(),
        set
    );
}

#[test]
fn an_expected_commitment_must_match_the_keys() {
    let keys = seed_keys(4);
    let right = digest(&review_vector("valset n=4 commitment"));
    assert!(AuthenticatedValidatorSet::with_expected_commitment(right, &keys).is_ok());
    let mut wrong = right;
    wrong[31] ^= 1;
    assert_eq!(
        AuthenticatedValidatorSet::with_expected_commitment(wrong, &keys),
        Err(ValidatorSetError::CommitmentMismatch)
    );
    // The n=2 commitment does not name the n=4 set, nor the reverse.
    let two = digest(&review_vector("valset n=2 commitment"));
    assert_eq!(
        AuthenticatedValidatorSet::with_expected_commitment(two, &keys),
        Err(ValidatorSetError::CommitmentMismatch)
    );
    assert_eq!(
        AuthenticatedValidatorSet::with_expected_commitment(right, &keys[..2]),
        Err(ValidatorSetError::CommitmentMismatch)
    );
    // A set's own construction rules are checked before the commitment.
    let mut dup = keys.clone();
    dup.push(keys[0]);
    assert_eq!(
        AuthenticatedValidatorSet::with_expected_commitment(right, &dup),
        Err(ValidatorSetError::Duplicate {
            first: 0,
            second: 4
        })
    );
}

// ------------------------------------------------------------ refusals ----

/// Every derivation entry point refuses `keys` with `want`.
fn all_refuse(keys: &[[u8; 32]], want: ValidatorSetError) {
    assert_eq!(validator_set_commitment(keys), Err(want));
    assert_eq!(validator_set_preimage(keys), Err(want));
    assert_eq!(AuthenticatedValidatorSet::from_keys(keys), Err(want));
    assert_eq!(
        AuthenticatedValidatorSet::with_expected_commitment([0; 32], keys),
        Err(want)
    );
    assert_eq!(AuthenticatedValidatorSet::new([0; 32], keys), Err(want));
}

#[test]
fn the_count_is_checked_before_any_key() {
    all_refuse(&[], ValidatorSetError::Empty);
    // 65,536 copies of an invalid key: refused by count, not by the key.
    let too_many = vec![[0u8; 32]; usize::from(MAX_VALIDATORS) + 1];
    all_refuse(&too_many, ValidatorSetError::TooMany { n: 65_536 });
}

#[test]
fn n_equal_one_is_a_set() {
    let keys = seed_keys(1);
    let preimage = validator_set_preimage(&keys).unwrap();
    assert_eq!(preimage.len(), 53);
    assert_eq!(&preimage[19..21], &[1, 0]);
    assert!(AuthenticatedValidatorSet::from_keys(&keys).is_ok());
}

#[test]
fn small_order_non_canonical_undecodable_and_duplicate_keys_are_refused() {
    let good = seed_keys(4);
    // Small order: the identity and the order-2 point.
    let identity = {
        let mut b = [0u8; 32];
        b[0] = 1;
        b
    };
    let mut order_two = [0xffu8; 32];
    order_two[0] = 0xec;
    order_two[31] = 0x7f;
    for weak in [identity, order_two] {
        let mut set = good.clone();
        set.insert(2, weak);
        all_refuse(&set, ValidatorSetError::SmallOrder { index: 2 });
    }
    // Non-canonical: y = p + 1, an encoding of the identity.
    let mut y_plus_p = [0xffu8; 32];
    y_plus_p[0] = 0xee;
    y_plus_p[31] = 0x7f;
    let mut set = good.clone();
    set.push(y_plus_p);
    let got = validator_set_commitment(&set);
    assert!(
        matches!(
            got,
            Err(ValidatorSetError::NonCanonical { index: 4 })
                | Err(ValidatorSetError::Undecodable { index: 4 })
        ),
        "{got:?}"
    );
    // Undecodable: the first small y that is not on the curve.
    let undecodable = (2u8..=255)
        .map(|y| {
            let mut b = [0u8; 32];
            b[0] = y;
            b
        })
        .find(|b| VerifyingKey::from_bytes(b).is_err())
        .expect("some y is not on the curve");
    let mut set = good.clone();
    set.insert(1, undecodable);
    all_refuse(&set, ValidatorSetError::Undecodable { index: 1 });
    // Duplicate.
    let mut set = good.clone();
    set.push(good[2]);
    all_refuse(
        &set,
        ValidatorSetError::Duplicate {
            first: 2,
            second: 4,
        },
    );
}

/// The full 65,535-key set: preimage 2,097,141 bytes. Slow in debug builds
/// (65,535 key derivations and point checks), so opt-in.
#[test]
#[ignore = "builds 65,535 keys; run with --ignored"]
fn the_cap_is_a_set() {
    let keys = many_keys(usize::from(MAX_VALIDATORS));
    let preimage = validator_set_preimage(&keys).unwrap();
    assert_eq!(preimage.len(), 2_097_141);
    assert_eq!(&preimage[19..21], &[0xff, 0xff]);
    let set = AuthenticatedValidatorSet::from_keys(&keys).unwrap();
    assert_eq!(set.len(), MAX_VALIDATORS);
    assert_eq!(*set.commitment(), *blake3::hash(&preimage).as_bytes());
}
