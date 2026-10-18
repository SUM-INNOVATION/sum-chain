//! The validator-count cap `1 ≤ n ≤ 65,535` (owner, 2026-10-18, for this
//! dormant protocol version) and the quorum arithmetic it feeds.
//!
//! Every place in this crate that represents a validator count as a `u16` uses
//! one check, `certificate::checked_validator_count`:
//!
//! * `vote::AuthenticatedValidatorSet::new` (the vote's authenticated set);
//! * `certificate::check_signers` (D2: the certificate's implied `n`).
//!
//! The quorum is `q(n) = ⌊2n/3⌋ + 1` (G2-c, ratified 2026-10-16: "⌊2n/3⌋+1
//! distinct validators"; D2's `certificate::quorum`), the least count strictly
//! greater than two-thirds of `n`.
//!
//! Keys are test-only: seed keys `[i; 32]`, and multiples `k·A` of one seed
//! key's point for the full-size set.

use std::sync::OnceLock;

use ed25519_dalek::{Signer, SigningKey};
use sumchain_finality_foundations::bootstrap::Membership;
use sumchain_finality_foundations::certificate::{
    check_signers, checked_validator_count, quorum, SignerSetError, ValidatorCountError,
    ValidatorSetResolver, MAX_VALIDATORS,
};
use sumchain_finality_foundations::encoding::Round;
use sumchain_finality_foundations::vote::{
    self, verify, AuthenticatedValidatorSet, CertificateRefusal, FinalityVoteV1,
    SignedFinalityVoteV1, TallyOutcome, ValidatorSetError, VoteContext, VoteTally, VoteType,
    VoteVerifyError,
};
use sumchain_finality_foundations::Digest;

const CONFIG: Digest = [0xc0; 32];
const BLOCK: Digest = [0xb1; 32];
const HEIGHT: u64 = 7;

struct Ctx(AuthenticatedValidatorSet);

impl VoteContext for Ctx {
    fn consensus_config_commitment(&self, height: u64) -> Option<Digest> {
        (height == HEIGHT).then_some(CONFIG)
    }
    fn validator_set(&self, height: u64) -> Option<&AuthenticatedValidatorSet> {
        (height == HEIGHT).then_some(&self.0)
    }
}

struct Fixed(Digest, u16);

impl ValidatorSetResolver for Fixed {
    fn validator_count(&self, commitment: &Digest) -> Option<u16> {
        (commitment == &self.0).then_some(self.1)
    }
}

fn seed(i: u8) -> SigningKey {
    SigningKey::from_bytes(&[i; 32])
}

/// Seed keys `[1; 32]..[n; 32]`, for `n ≤ 255`.
fn seed_keys(n: u8) -> Vec<[u8; 32]> {
    (1..=n)
        .map(|i| seed(i).verifying_key().to_bytes())
        .collect()
}

/// A precommit for `BLOCK` at `HEIGHT`, round 0, by `index`, signed by `key`.
fn precommit(valset: Digest, index: u16, key: &SigningKey) -> SignedFinalityVoteV1 {
    let vote = FinalityVoteV1 {
        consensus_config_commitment: CONFIG,
        height: HEIGHT,
        block_id: BLOCK,
        round: Round::ZERO,
        vote_type: VoteType::Precommit,
        validator_set_commitment: valset,
        validator_index: index,
    };
    SignedFinalityVoteV1 {
        vote,
        signature: key.sign(&vote.preimage()).to_bytes(),
    }
}

/// `n` distinct, canonical, prime-order keys: `k·A` for `k = 1..=n`, where `A`
/// is the point of seed key `[0x11; 32]`. With `last`, the final key is
/// replaced by that seed key, so a vote at the last index can be signed.
fn generated_keys(n: usize, last: Option<u8>) -> Vec<[u8; 32]> {
    let a = seed(0x11).verifying_key().to_edwards();
    let mut p = a;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(p.compress().to_bytes());
        p += a;
    }
    if let (Some(s), Some(k)) = (last, out.last_mut()) {
        *k = seed(s).verifying_key().to_bytes();
    }
    out
}

const CAP_SET: Digest = [0xca; 32];
const CAP_SEED: u8 = 0x77;

/// 65,535 distinct valid keys, the last one seed `CAP_SEED`, built once.
fn cap_keys() -> &'static [[u8; 32]] {
    static KEYS: OnceLock<Vec<[u8; 32]>> = OnceLock::new();
    KEYS.get_or_init(|| generated_keys(usize::from(MAX_VALIDATORS), Some(CAP_SEED)))
}

/// The full-size set of [`cap_keys`], built once.
fn cap_set() -> &'static AuthenticatedValidatorSet {
    static SET: OnceLock<AuthenticatedValidatorSet> = OnceLock::new();
    SET.get_or_init(|| {
        AuthenticatedValidatorSet::new(CAP_SET, cap_keys()).expect("65,535 valid keys are accepted")
    })
}

// ------------------------------------------------------- the shared cap ----

#[test]
fn one_shared_cap_of_65535() {
    assert_eq!(MAX_VALIDATORS, 65_535);
    assert_eq!(MAX_VALIDATORS, u16::MAX);
    assert_eq!(
        vote::MAX_VALIDATORS,
        MAX_VALIDATORS,
        "the vote re-exports the one constant"
    );
    assert_eq!(checked_validator_count(0), Err(ValidatorCountError::Empty));
    assert_eq!(checked_validator_count(1), Ok(1));
    assert_eq!(checked_validator_count(65_534), Ok(65_534));
    assert_eq!(checked_validator_count(65_535), Ok(65_535));
    for n in [65_536usize, 65_537, 100_000, u32::MAX as usize, usize::MAX] {
        assert_eq!(
            checked_validator_count(n),
            Err(ValidatorCountError::TooMany { n }),
            "n = {n}"
        );
    }
    // Every u16 count other than 0 passes, so a u16 can never carry a count the
    // cap refuses: the certificate's `n` is bounded by its type and this check.
    for n in 1..=u16::MAX {
        assert_eq!(checked_validator_count(usize::from(n)), Ok(n));
    }
}

#[test]
fn a_set_of_one() {
    let keys = seed_keys(1);
    let set = AuthenticatedValidatorSet::new([1; 32], &keys).unwrap();
    assert_eq!(set.len(), 1);
    assert_eq!(quorum(1), 1);
    let ctx = Ctx(set.clone());
    let only = verify(&precommit([1; 32], 0, &seed(1)), &ctx).expect("index 0 of 1");
    for index in [1u16, 2, u16::MAX] {
        assert_eq!(
            verify(&precommit([1; 32], index, &seed(1)), &ctx),
            Err(VoteVerifyError::IndexOutOfRange { index, n: 1 })
        );
    }
    let mut tally = VoteTally::new(&set);
    assert_eq!(tally.insert(&only), Ok(TallyOutcome::Counted));
    let signers = tally
        .certificate_signers(&CONFIG, HEIGHT, Round::ZERO, &BLOCK)
        .unwrap();
    assert_eq!(signers.indices(), &[0]);
    assert_eq!(signers.validator_count(), 1);
    assert_eq!(
        check_signers(&[1; 32], &[], &Fixed([1; 32], 1)),
        Err(SignerSetError::BelowQuorum {
            k: 0,
            quorum: 1,
            n: 1
        })
    );
}

#[test]
fn a_set_of_65535_is_accepted_and_index_65535_is_out_of_range() {
    let set = cap_set();
    assert_eq!(set.len(), 65_535);
    assert!(set.key(65_534).is_some());
    assert!(set.key(65_535).is_none());
    let ctx = Ctx(set.clone());
    // The last valid index, 65,534, verifies under the set's last key.
    let last =
        verify(&precommit(CAP_SET, 65_534, &seed(CAP_SEED)), &ctx).expect("index 65,534 of 65,535");
    assert_eq!(last.vote().validator_index, 65_534);
    // 65,535 is the largest u16 and is out of range even at the cap.
    assert_eq!(
        verify(&precommit(CAP_SET, 65_535, &seed(CAP_SEED)), &ctx),
        Err(VoteVerifyError::IndexOutOfRange {
            index: 65_535,
            n: 65_535
        })
    );
    // The decoded wire form of that vote is well formed; only the context
    // check refuses it.
    let wire = precommit(CAP_SET, 65_535, &seed(CAP_SEED)).to_wire();
    let decoded = SignedFinalityVoteV1::from_wire(&wire).unwrap();
    assert_eq!(decoded.vote.validator_index, u16::MAX);
    assert_eq!(
        vote::decode_and_verify(&wire, &ctx),
        Err(vote::VoteError::Verify(VoteVerifyError::IndexOutOfRange {
            index: 65_535,
            n: 65_535
        }))
    );
    // The tally takes the set's n, and a certificate needs q(65,535) = 43,691.
    let mut tally = VoteTally::new(set);
    assert_eq!(tally.insert(&last), Ok(TallyOutcome::Counted));
    assert_eq!(
        tally.certificate_signers(&CONFIG, HEIGHT, Round::ZERO, &BLOCK),
        Err(CertificateRefusal::Signers(SignerSetError::BelowQuorum {
            k: 1,
            quorum: 43_691,
            n: 65_535
        }))
    );
}

#[test]
fn a_count_of_65536_is_refused_at_every_construction_point() {
    // The vote's authenticated set: 65,536 and 65,537 distinct valid keys
    // (the 65,535 accepted ones plus one or two more seed keys).
    for extra in [vec![0x78u8], vec![0x78, 0x79]] {
        let mut keys = cap_keys().to_vec();
        keys.extend(extra.iter().map(|&s| seed(s).verifying_key().to_bytes()));
        let n = keys.len();
        assert_eq!(
            AuthenticatedValidatorSet::new([2; 32], &keys),
            Err(ValidatorSetError::TooMany { n }),
            "n = {n}"
        );
    }
    // The shared check, which both construction points use.
    assert_eq!(
        checked_validator_count(65_536),
        Err(ValidatorCountError::TooMany { n: 65_536 })
    );
    // The certificate's n is a u16 from the resolver, so 65,536 cannot be
    // expressed there, and the largest expressible count is accepted.
    assert!(u16::try_from(65_536usize).is_err());
    let all: Vec<u16> = (0..u16::MAX).collect();
    let signers = check_signers(&[3; 32], &all, &Fixed([3; 32], u16::MAX)).unwrap();
    assert_eq!(signers.validator_count(), 65_535);
    // More than n entries is refused before anything else.
    let mut too_many = all.clone();
    too_many.push(0);
    assert_eq!(
        check_signers(&[3; 32], &too_many, &Fixed([3; 32], u16::MAX)),
        Err(SignerSetError::AboveSetSize {
            k: 65_536,
            n: 65_535
        })
    );
    // Zero is refused at both points.
    assert_eq!(
        AuthenticatedValidatorSet::new([2; 32], &[]),
        Err(ValidatorSetError::Empty)
    );
    assert_eq!(
        check_signers(&[3; 32], &[], &Fixed([3; 32], 0)),
        Err(SignerSetError::EmptyValidatorSet)
    );
}

#[test]
fn invalid_indices_for_every_small_n() {
    for n in 1u8..=10 {
        let keys = seed_keys(n);
        let ctx = Ctx(AuthenticatedValidatorSet::new([n; 32], &keys).unwrap());
        let n16 = u16::from(n);
        // n - 1 is the last valid index and verifies under seed n.
        verify(&precommit([n; 32], n16 - 1, &seed(n)), &ctx).expect("index n - 1");
        for index in [n16, n16 + 1, u16::MAX] {
            assert_eq!(
                verify(&precommit([n; 32], index, &seed(n)), &ctx),
                Err(VoteVerifyError::IndexOutOfRange { index, n: n16 }),
                "n = {n}, index = {index}"
            );
        }
    }
}

// ---------------------------------------------------- quorum arithmetic ----

#[test]
fn quorum_is_the_least_count_strictly_above_two_thirds_for_every_n() {
    for n in 1..=u16::MAX {
        let q = u64::from(quorum(n));
        let n64 = u64::from(n);
        assert!(3 * q > 2 * n64, "n = {n}: q = {q} is not above 2n/3");
        assert!(
            3 * (q - 1) <= 2 * n64,
            "n = {n}: q - 1 = {} is already above 2n/3",
            q - 1
        );
        assert!(q <= n64, "n = {n}: q = {q} exceeds n");
        assert_eq!(q, n64 * 2 / 3 + 1, "n = {n}: q = ⌊2n/3⌋ + 1");
    }
}

#[test]
fn quorum_edges() {
    let table: [(u16, u16); 10] = [
        (1, 1),
        (2, 2),
        (3, 3),
        (4, 3),
        (5, 4),
        (6, 5),
        (7, 5),
        (8, 6),
        (9, 7),
        (10, 7),
    ];
    for (n, q) in table {
        assert_eq!(quorum(n), q, "n = {n}");
    }
    // n = 3f + 1 tolerates f faults with a quorum of 2f + 1, up to the cap.
    for f in 0u16..=21_844 {
        assert_eq!(quorum(3 * f + 1), 2 * f + 1, "f = {f}");
    }
    assert_eq!(3 * 21_844 + 1, 65_533);
    // n = 3f and 3f + 2.
    for f in 1u16..=21_845 {
        assert_eq!(quorum(3 * f), 2 * f + 1, "n = 3f, f = {f}");
    }
    for f in 0u16..=21_844 {
        assert_eq!(quorum(3 * f + 2), 2 * f + 2, "n = 3f + 2, f = {f}");
    }
    assert_eq!(quorum(65_534), 43_690);
    assert_eq!(quorum(u16::MAX), 43_691);
    assert_eq!(3 * 43_691u32, 131_073);
    assert_eq!(2 * 65_535u32, 131_070);
}

#[test]
fn certificate_threshold_is_exactly_the_quorum() {
    for n in (1u16..=10).chain([64, 100, 65_534, u16::MAX]) {
        let q = quorum(n);
        let resolver = Fixed([4; 32], n);
        let at: Vec<u16> = (0..q).collect();
        let signers = check_signers(&[4; 32], &at, &resolver)
            .unwrap_or_else(|e| panic!("n = {n}: q = {q} signers refused: {e}"));
        assert_eq!(signers.indices().len(), usize::from(q));
        let below: Vec<u16> = (0..q - 1).collect();
        assert_eq!(
            check_signers(&[4; 32], &below, &resolver),
            Err(SignerSetError::BelowQuorum {
                k: usize::from(q - 1),
                quorum: q,
                n
            }),
            "n = {n}"
        );
        let all: Vec<u16> = (0..n).collect();
        assert!(
            check_signers(&[4; 32], &all, &resolver).is_ok(),
            "n = {n}: all n"
        );
    }
}

#[test]
fn the_bootstrap_quorum_uses_the_same_formula_at_the_cap() {
    for n in [1usize, 2, 3, 4, 10, 100, 65_534, 65_535] {
        let m = Membership {
            members: vec![Vec::new(); n],
            commitment: [0; 32],
        };
        assert_eq!(m.quorum(), usize::from(quorum(n as u16)), "n = {n}");
    }
}
