//! PROPOSED, UNRATIFIED: the proofs the signer verifies itself, with real
//! Ed25519 signatures from synthetic keys (seeds `[0x01; 32]`..).
//!
//! * `PolkaProofV1` (the prevote quorum): KAT vectors in
//!   `tests/vectors/polka_proof_v1.json`, regenerated and compared here; the
//!   refusal list; sizes by `k`.
//! * Height advancement through `ConsensusProofs` with ratified
//!   `FinalityCertificateV1` certificates: valid, forged, insufficient, wrong
//!   set, wrong height, stale and conflicting.
//! * Lock changes justified by a real `PolkaProofV1`.
//! * The evidence floor at open, taken from a verified certificate.
//! * Recovery after a conflict halt: refused for an insufficient, forged,
//!   wrong-fork, non-certificate or too-low resume certificate and for bad
//!   evidence; accepted for a verified certificate at or above the halted
//!   working height.

use std::collections::BTreeMap;
use std::rc::Rc;

use ed25519_dalek::{Signer as _, SigningKey as EdSigningKey};
use serde_json::{json, Value};
use sumchain_finality_foundations::certificate::{
    certificate_len, quorum, CertificateEntry, FinalityCertificateV1, CERT_MAGIC, MAX_VALIDATORS,
};
use sumchain_finality_foundations::encoding::{Round, MAX_ROUND};
use sumchain_finality_foundations::proofs::{
    decode_and_verify_polka_proof, polka_proof_len, ConsensusProofs, PolkaDecodeError, PolkaError,
    PolkaProofV1, PolkaVerifyError, MAX_POLKA_LEN, POLKA_MAGIC,
};
use sumchain_finality_foundations::signer::{
    initialize_exclusive, Certified, DurableSigner, Justification, SignPosition, SignRequest,
    SignerError, SigningKey, Step, VoteValue,
};
use sumchain_finality_foundations::signer_file::{floor_below_height, FileSignerStore};
use sumchain_finality_foundations::vote::{
    AuthenticatedValidatorSet, FinalityVoteV1, VoteContext, VoteType,
};
use sumchain_finality_foundations::Digest;

mod common;
use common::*;

const CONFIG: Digest = [0xc0; 32];
const CHAIN: u64 = 4242;
const GENESIS: Digest = [0x11; 32];
const X: Digest = [0xb1; 32];
const Y: Digest = [0xb2; 32];

fn seed_key(index: u16) -> EdSigningKey {
    EdSigningKey::from_bytes(&[u8::try_from(index + 1).expect("small test set"); 32])
}

fn valset_commitment(n: u16) -> Digest {
    let mut d = [0x5au8; 32];
    d[..2].copy_from_slice(&n.to_le_bytes());
    d
}

/// The node's authenticated view: one static set of `n` for heights 1..=20.
struct Ctx {
    config: Digest,
    sets: BTreeMap<u64, AuthenticatedValidatorSet>,
}

impl Ctx {
    fn new(n: u16) -> Ctx {
        let keys: Vec<[u8; 32]> = (0..n)
            .map(|i| seed_key(i).verifying_key().to_bytes())
            .collect();
        let set = AuthenticatedValidatorSet::new(valset_commitment(n), &keys).expect("valid set");
        Ctx {
            config: CONFIG,
            sets: (1..=20).map(|h| (h, set.clone())).collect(),
        }
    }
}

impl VoteContext for Ctx {
    fn consensus_config_commitment(&self, height: u64) -> Option<Digest> {
        self.sets.contains_key(&height).then_some(self.config)
    }
    fn validator_set(&self, height: u64) -> Option<&AuthenticatedValidatorSet> {
        self.sets.get(&height)
    }
}

fn vote(
    vote_type: VoteType,
    n: u16,
    height: u64,
    round: u32,
    block: Digest,
    index: u16,
) -> FinalityVoteV1 {
    FinalityVoteV1 {
        consensus_config_commitment: CONFIG,
        height,
        block_id: block,
        round: Round::new(round).unwrap(),
        vote_type,
        validator_set_commitment: valset_commitment(n),
        validator_index: index,
    }
}

fn entries(
    vote_type: VoteType,
    n: u16,
    height: u64,
    round: u32,
    block: Digest,
    signers: &[u16],
) -> Vec<CertificateEntry> {
    signers
        .iter()
        .map(|&i| CertificateEntry {
            validator_index: i,
            signature: seed_key(i)
                .sign(&vote(vote_type, n, height, round, block, i).preimage())
                .to_bytes(),
        })
        .collect()
}

fn polka(n: u16, height: u64, round: u32, block: Digest, signers: &[u16]) -> PolkaProofV1 {
    PolkaProofV1 {
        consensus_config_commitment: CONFIG,
        height,
        block_id: block,
        round: Round::new(round).unwrap(),
        validator_set_commitment: valset_commitment(n),
        entries: entries(VoteType::Prevote, n, height, round, block, signers),
    }
}

fn cert(n: u16, height: u64, round: u32, block: Digest, signers: &[u16]) -> FinalityCertificateV1 {
    FinalityCertificateV1 {
        consensus_config_commitment: CONFIG,
        height,
        block_id: block,
        round: Round::new(round).unwrap(),
        validator_set_commitment: valset_commitment(n),
        entries: entries(VoteType::Precommit, n, height, round, block, signers),
    }
}

// ── PolkaProofV1 KAT vectors ────────────────────────────────────────────────

const VECTORS: &str = include_str!("vectors/polka_proof_v1.json");

struct Kat {
    name: &'static str,
    n: u16,
    height: u64,
    round: u32,
    signers: &'static [u16],
}

const KATS: [Kat; 3] = [
    Kat {
        name: "polka n=4 h=7 r=1 signers {0,1,3} (minimum quorum k=3)",
        n: 4,
        height: 7,
        round: 1,
        signers: &[0, 1, 3],
    },
    Kat {
        name: "polka n=4 h=7 r=1 signers {0,1,2,3} (all signers k=4)",
        n: 4,
        height: 7,
        round: 1,
        signers: &[0, 1, 2, 3],
    },
    Kat {
        name: "polka n=2 h=7 r=0 signers {0,1} (k=2)",
        n: 2,
        height: 7,
        round: 0,
        signers: &[0, 1],
    },
];

fn kat_json() -> Value {
    let vectors: Vec<Value> = KATS
        .iter()
        .map(|k| {
            let bytes = polka(k.n, k.height, k.round, X, k.signers)
                .encode()
                .unwrap();
            json!({
                "name": k.name,
                "n": k.n,
                "k": k.signers.len(),
                "signers": k.signers,
                "height": k.height,
                "round": k.round,
                "block_id": hex::encode(X),
                "consensus_config_commitment": hex::encode(CONFIG),
                "validator_set_commitment": hex::encode(valset_commitment(k.n)),
                "length": bytes.len(),
                "hex": hex::encode(&bytes),
            })
        })
        .collect();
    json!({
        "title": "PolkaProofV1 (UNRATIFIED) known-answer vectors",
        "status": "UNRATIFIED PROPOSAL. SYNTHETIC: test-only Ed25519 seeds [0x01;32]..[0x04;32]; config, set commitment and block are synthetic.",
        "magic": hex::encode(POLKA_MAGIC),
        "vectors": vectors,
    })
}

/// Regenerate the vector file: `SUMCHAIN_WRITE_POLKA_VECTORS=1 cargo test ...`.
#[test]
fn polka_kat_vectors_match_and_verify() {
    let generated = kat_json();
    if std::env::var_os("SUMCHAIN_WRITE_POLKA_VECTORS").is_some() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/vectors/polka_proof_v1.json"
        );
        std::fs::write(
            path,
            serde_json::to_string_pretty(&generated).unwrap() + "\n",
        )
        .unwrap();
    }
    let committed: Value = serde_json::from_str(VECTORS).expect("vectors are JSON");
    assert_eq!(
        committed, generated,
        "the committed vectors are what the code produces"
    );
    for (k, v) in KATS.iter().zip(committed["vectors"].as_array().unwrap()) {
        let bytes = hex::decode(v["hex"].as_str().unwrap()).unwrap();
        assert_eq!(bytes.len(), polka_proof_len(k.signers.len() as u16));
        assert_eq!(&bytes[..7], b"FPOLv1\0");
        let decoded = PolkaProofV1::decode(&bytes).unwrap();
        assert_eq!(decoded.encode().unwrap(), bytes);
        decode_and_verify_polka_proof(&bytes, k.height, k.round, &X, &Ctx::new(k.n))
            .unwrap_or_else(|e| panic!("{}: {e}", k.name));
    }
}

#[test]
fn polka_sizes_by_k() {
    assert_eq!(hex::encode(POLKA_MAGIC), "46504f4c763100");
    assert_eq!(polka_proof_len(3), 317, "n=4 minimum quorum");
    assert_eq!(polka_proof_len(4), 383, "n=4 all signers");
    assert_eq!(polka_proof_len(2), 251, "n=2");
    assert_eq!(quorum(MAX_VALIDATORS), 43_691);
    assert_eq!(
        polka_proof_len(quorum(MAX_VALIDATORS)),
        2_883_725,
        "cap, minimum quorum"
    );
    assert_eq!(MAX_POLKA_LEN, 4_325_429, "cap, all signers");
    assert_eq!(polka_proof_len(7), certificate_len(7), "same framing as C");
}

// ── PolkaProofV1 refusals ───────────────────────────────────────────────────

#[test]
fn polka_refusals() {
    let ctx = Ctx::new(4);
    let good = polka(4, 7, 1, X, &[0, 1, 3]);
    let bytes = good.encode().unwrap();
    let check =
        |b: &[u8], h: u64, r: u32, v: &Digest| decode_and_verify_polka_proof(b, h, r, v, &ctx);
    assert!(check(&bytes, 7, 1, &X).is_ok());

    // Decoding.
    let dec = |b: &[u8]| match check(b, 7, 1, &X) {
        Err(PolkaError::Decode(e)) => e,
        other => panic!("expected a decode refusal, got {other:?}"),
    };
    assert_eq!(
        dec(&bytes[..118]),
        PolkaDecodeError::ShortHeader { actual: 118 }
    );
    let mut b = bytes.clone();
    b[0..7].copy_from_slice(&CERT_MAGIC);
    assert_eq!(
        dec(&b),
        PolkaDecodeError::Magic,
        "a certificate is not a polka"
    );
    let mut b = bytes.clone();
    b[7] = 2;
    assert_eq!(dec(&b), PolkaDecodeError::Schema(2));
    assert!(matches!(
        dec(&[bytes.clone(), vec![0]].concat()),
        PolkaDecodeError::Length { .. }
    ));
    let mut b = bytes[..119].to_vec();
    b[117..119].copy_from_slice(&u16::MAX.to_le_bytes());
    assert!(
        matches!(dec(&b), PolkaDecodeError::Length { k: u16::MAX, .. }),
        "an over-declared k is refused on length, before entries are read"
    );
    let mut b = bytes.clone();
    b[81..85].copy_from_slice(&(MAX_ROUND + 1).to_le_bytes());
    assert!(matches!(dec(&b), PolkaDecodeError::Round(_)));
    let mut b = bytes.clone();
    b[49..81].fill(0);
    assert_eq!(dec(&b), PolkaDecodeError::NilBlock);
    let mut swapped = good.clone();
    swapped.entries.swap(0, 1);
    let mut b = bytes.clone();
    b[119..119 + 66].copy_from_slice(
        &[
            &swapped.entries[0].validator_index.to_le_bytes()[..],
            &swapped.entries[0].signature[..],
        ]
        .concat(),
    );
    b[185..185 + 66].copy_from_slice(
        &[
            &swapped.entries[1].validator_index.to_le_bytes()[..],
            &swapped.entries[1].signature[..],
        ]
        .concat(),
    );
    assert!(matches!(
        dec(&b),
        PolkaDecodeError::NotStrictlyAscending { .. }
    ));

    // Verification.
    let ver = |b: &[u8], h: u64, r: u32, v: &Digest| match check(b, h, r, v) {
        Err(PolkaError::Verify(e)) => e,
        other => panic!("expected a verify refusal, got {other:?}"),
    };
    assert!(matches!(
        ver(&bytes, 8, 1, &X),
        PolkaVerifyError::HeightMismatch { .. }
    ));
    assert!(matches!(
        ver(&bytes, 7, 2, &X),
        PolkaVerifyError::RoundMismatch { .. }
    ));
    assert_eq!(ver(&bytes, 7, 1, &Y), PolkaVerifyError::BlockMismatch);
    let insufficient = polka(4, 7, 1, X, &[0, 1]).encode().unwrap();
    assert!(matches!(
        ver(&insufficient, 7, 1, &X),
        PolkaVerifyError::Signers(_)
    ));
    let mut other_set = good.clone();
    other_set.validator_set_commitment = valset_commitment(5);
    assert_eq!(
        ver(&other_set.encode().unwrap(), 7, 1, &X),
        PolkaVerifyError::ValidatorSetCommitmentMismatch
    );
    let mut other_config = good.clone();
    other_config.consensus_config_commitment = [0xc1; 32];
    assert_eq!(
        ver(&other_config.encode().unwrap(), 7, 1, &X),
        PolkaVerifyError::ConfigCommitmentMismatch
    );
    let unknown_height = polka(4, 99, 1, X, &[0, 1, 3]).encode().unwrap();
    assert!(matches!(
        ver(&unknown_height, 99, 1, &X),
        PolkaVerifyError::NoConfigCommitment { height: 99 }
    ));
    let mut forged = good.clone();
    forged.entries[1].signature[10] ^= 1;
    assert_eq!(
        ver(&forged.encode().unwrap(), 7, 1, &X),
        PolkaVerifyError::Signature { index: 1 }
    );
    // Precommit signatures (a certificate's) transplanted into a polka fail:
    // the vote type is part of what each signature covers.
    let mut transplanted = good.clone();
    transplanted.entries = cert(4, 7, 1, X, &[0, 1, 3]).entries;
    assert_eq!(
        ver(&transplanted.encode().unwrap(), 7, 1, &X),
        PolkaVerifyError::Signature { index: 0 }
    );
    // Signed by keys outside the authenticated set.
    let mut outsiders = good.clone();
    outsiders.entries = (0..3u16)
        .map(|i| CertificateEntry {
            validator_index: i,
            signature: EdSigningKey::from_bytes(&[0x40 + i as u8; 32])
                .sign(&vote(VoteType::Prevote, 4, 7, 1, X, i).preimage())
                .to_bytes(),
        })
        .collect();
    assert!(matches!(
        ver(&outsiders.encode().unwrap(), 7, 1, &X),
        PolkaVerifyError::Signature { .. }
    ));
}

// ── height advancement and lock changes with real proofs ────────────────────

struct Key(EdSigningKey);
impl SigningKey for Key {
    fn key_id(&self) -> Digest {
        self.0.verifying_key().to_bytes()
    }
    fn sign(&self, payload: &[u8]) -> Vec<u8> {
        self.0.sign(payload).to_bytes().to_vec()
    }
}

type Store = FileSignerStore<SimDir, SimMirror, B3>;
type RealSigner = DurableSigner<Store, Key, ConsensusProofs<Ctx>, MemGuard>;

struct Rig {
    disk: Disk,
    owner: MemOwnership,
}

impl Rig {
    /// Validator 1 of a 4-validator set, initialized to work at height 7.
    fn new() -> Rig {
        let rig = Rig {
            disk: Rc::default(),
            owner: MemOwnership::default(),
        };
        initialize_exclusive(
            &rig.owner,
            &mut rig.store(),
            Key(seed_key(1)).key_id(),
            floor_below_height(7),
        )
        .unwrap();
        rig
    }
    fn store(&self) -> Store {
        FileSignerStore::new(
            SimDir(self.disk.clone()),
            SimMirror(self.disk.clone()),
            B3,
            CHAIN,
            GENESIS,
        )
    }
    fn open(&self, evidence: Option<SignPosition>) -> Result<RealSigner, SignerError> {
        DurableSigner::open(
            &self.owner,
            self.store(),
            Key(seed_key(1)),
            ConsensusProofs::new(Ctx::new(4)),
            evidence,
        )
    }
    fn writes(&self) -> usize {
        self.disk.borrow().ops
    }
}

/// The signer's own vote at (h, r) as ratified V bytes.
fn own(vote_type: VoteType, h: u64, r: u32, value: Option<Digest>) -> SignRequest {
    let block = value.unwrap_or([0; 32]);
    SignRequest {
        position: SignPosition {
            height: h,
            round: r,
            step: vote_type.step(),
        },
        value: value.map_or(VoteValue::Nil, VoteValue::Block),
        payload: vote(vote_type, 4, h, r, block, 1).preimage().to_vec(),
        justification: None,
    }
}

fn with_polka(mut r: SignRequest, polka_round: u32, proof: &PolkaProofV1) -> SignRequest {
    r.justification = Some(Justification {
        polka_round,
        evidence: proof.encode().unwrap(),
    });
    r
}

/// Locked on X at (7, 0).
fn locked() -> (Rig, RealSigner) {
    let rig = Rig::new();
    let mut s = rig.open(None).unwrap();
    s.sign(&own(VoteType::Prevote, 7, 0, Some(X))).unwrap();
    s.sign(&with_polka(
        own(VoteType::Precommit, 7, 0, Some(X)),
        0,
        &polka(4, 7, 0, X, &[0, 2, 3]),
    ))
    .unwrap();
    (rig, s)
}

#[test]
fn advancement_needs_a_verified_certificate_for_the_working_height_or_above() {
    let (rig, mut s) = locked();
    let refused: Vec<(&str, Vec<u8>)> = vec![
        ("not a certificate", b"advance please".to_vec()),
        (
            "a polka is not a certificate",
            polka(4, 7, 0, X, &[0, 2, 3]).encode().unwrap(),
        ),
        (
            "insufficient: k < q(n)",
            cert(4, 7, 0, X, &[0, 2]).encode().unwrap(),
        ),
        ("forged signature", {
            let mut c = cert(4, 7, 0, X, &[0, 2, 3]);
            c.entries[2].signature[0] ^= 1;
            c.encode().unwrap()
        }),
        ("wrong set commitment", {
            let mut c = cert(4, 7, 0, X, &[0, 2, 3]);
            c.validator_set_commitment = valset_commitment(5);
            c.encode().unwrap()
        }),
        ("signed by another set's keys", {
            let mut c = cert(4, 7, 0, X, &[0, 2, 3]);
            for e in &mut c.entries {
                e.signature = EdSigningKey::from_bytes(&[0x40 + e.validator_index as u8; 32])
                    .sign(&vote(VoteType::Precommit, 4, 7, 0, X, e.validator_index).preimage())
                    .to_bytes();
            }
            c.encode().unwrap()
        }),
        ("wrong config commitment", {
            let mut c = cert(4, 7, 0, X, &[0, 2, 3]);
            c.consensus_config_commitment = [0xc1; 32];
            c.encode().unwrap()
        }),
        (
            "a height with no authenticated set",
            cert(4, 99, 0, X, &[0, 2, 3]).encode().unwrap(),
        ),
    ];
    for (what, proof) in refused {
        let before = rig.writes();
        assert!(
            matches!(s.advance(&proof), Err(SignerError::InvalidFinalityProof(_))),
            "{what}"
        );
        assert_eq!(rig.writes(), before, "{what}: nothing written");
        assert_eq!(
            s.record().lock.map(|l| l.height),
            Some(7),
            "{what}: the lock stays"
        );
    }
    // A valid certificate for a height below the working height is stale.
    assert!(matches!(
        s.advance(&cert(4, 6, 0, Y, &[0, 1, 2]).encode().unwrap()),
        Err(SignerError::StaleFinalityProof {
            proof: 6,
            working: 7
        })
    ));
    // Asking to sign at height 8 is refused until a certificate for 7 verifies.
    assert!(matches!(
        s.sign(&own(VoteType::Prevote, 8, 0, Some(Y))),
        Err(SignerError::HeightNotCertified {
            requested: 8,
            working: 7
        })
    ));
    let c7 = cert(4, 7, 0, X, &[0, 2, 3]).encode().unwrap();
    assert_eq!(
        s.advance(&c7).unwrap(),
        Certified {
            height: 7,
            block_id: X
        }
    );
    assert_eq!(s.record().lock, None);
    s.sign(&own(VoteType::Prevote, 8, 0, Some(Y))).unwrap();

    // A second valid certificate for height 7 naming another block: two
    // verified finality proofs conflict. The halt is persisted, with the
    // conflicting certificate (trimmed to a quorum) kept as evidence.
    let conflicting = cert(4, 7, 3, Y, &[0, 1, 2, 3]).encode().unwrap();
    assert_eq!(
        s.advance(&conflicting),
        Err(SignerError::ConflictingFinality(7))
    );
    assert!(s.is_halted());
    let halt = s.record().halt.clone().unwrap();
    assert_eq!(
        (halt.height, halt.certified_block, halt.conflicting_block),
        (7, X, Some(Y))
    );
    assert!(matches!(
        s.sign(&own(VoteType::Prevote, 8, 1, Some(Y))),
        Err(SignerError::Halted)
    ));
    drop(s);
    let s = rig.open(None).unwrap();
    assert!(s.is_halted(), "the halt is durable");
    assert_eq!(
        s.store().proof_status(),
        sumchain_finality_foundations::signer_file::ProofStatus::Present,
        "the evidence file is durable"
    );
}

#[test]
fn catch_up_certificate_skips_heights_and_closes_them() {
    let (_rig, mut s) = locked();
    s.advance(&cert(4, 10, 2, Y, &[1, 2, 3]).encode().unwrap())
        .unwrap();
    assert_eq!(s.record().working_height(), Some(11));
    for h in [7, 8, 9, 10] {
        assert!(
            matches!(
                s.sign(&own(VoteType::Prevote, h, 0, Some(X))),
                Err(SignerError::Regression { .. })
            ),
            "height {h} is closed"
        );
    }
    s.sign(&own(VoteType::Prevote, 11, 0, Some(X))).unwrap();
}

#[test]
fn lock_change_needs_a_real_prevote_quorum() {
    let (_rig, mut s) = locked();
    let prevote_y = own(VoteType::Prevote, 7, 2, Some(Y));
    let refused: Vec<(&str, SignRequest)> = vec![
        ("no proof", prevote_y.clone()),
        (
            "proof for the wrong value",
            with_polka(prevote_y.clone(), 1, &polka(4, 7, 1, X, &[0, 2, 3])),
        ),
        (
            "insufficient proof",
            with_polka(prevote_y.clone(), 1, &polka(4, 7, 1, Y, &[0, 2])),
        ),
        ("forged proof", {
            let mut p = polka(4, 7, 1, Y, &[0, 2, 3]);
            p.entries[0].signature[5] ^= 1;
            with_polka(prevote_y.clone(), 1, &p)
        }),
        ("precommit signatures, not prevotes", {
            let mut p = polka(4, 7, 1, Y, &[0, 2, 3]);
            p.entries = cert(4, 7, 1, Y, &[0, 2, 3]).entries;
            with_polka(prevote_y.clone(), 1, &p)
        }),
        (
            "proof names another round than claimed",
            with_polka(prevote_y.clone(), 1, &polka(4, 7, 0, Y, &[0, 2, 3])),
        ),
    ];
    for (what, r) in refused {
        assert!(
            matches!(
                s.sign(&r),
                Err(SignerError::LockedOnOtherValue(_)) | Err(SignerError::InvalidJustification(_))
            ),
            "{what}"
        );
    }
    // A real quorum for Y at round 1 (lock round 0 ≤ 1 < 2) justifies it.
    s.sign(&with_polka(
        prevote_y.clone(),
        1,
        &polka(4, 7, 1, Y, &[0, 2, 3]),
    ))
    .unwrap();
    assert_eq!(
        s.record().lock.map(|l| (l.round, l.value)),
        Some((0, X)),
        "the lock stays"
    );
    // Relock to Y at round 2 needs a quorum in round 2 itself.
    let precommit_y = own(VoteType::Precommit, 7, 2, Some(Y));
    assert!(s
        .sign(&with_polka(
            precommit_y.clone(),
            1,
            &polka(4, 7, 1, Y, &[0, 2, 3])
        ))
        .is_err());
    s.sign(&with_polka(precommit_y, 2, &polka(4, 7, 2, Y, &[0, 1, 2])))
        .unwrap();
    assert_eq!(s.record().lock.map(|l| (l.round, l.value)), Some((2, Y)));
}

#[test]
fn evidence_floor_from_a_verified_certificate_catches_a_rolled_back_state() {
    let rig = Rig::new();
    let mut s = rig.open(None).unwrap();
    s.sign(&own(VoteType::Prevote, 7, 0, Some(X))).unwrap();
    // Save the state as of this point (an operator backup).
    let backup = rig.disk.borrow().clone();
    s.sign(&with_polka(
        own(VoteType::Precommit, 7, 0, Some(X)),
        0,
        &polka(4, 7, 0, X, &[0, 2, 3]),
    ))
    .unwrap();
    drop(s);
    // The chain has a certificate for (7, 0) that includes this key (index 1).
    let c = cert(4, 7, 0, X, &[0, 1, 2]);
    let verified =
        sumchain_finality_foundations::certificate::verify_certificate(&c, 7, &X, &Ctx::new(4))
            .unwrap();
    assert!(verified.signers().indices().contains(&1));
    let evidence = SignPosition {
        height: c.height,
        round: c.round.get(),
        step: Step::Precommit,
    };
    // Restoring the backup (state file and mirror together) is caught.
    *rig.disk.borrow_mut() = backup;
    assert!(matches!(
        rig.open(Some(evidence)),
        Err(SignerError::StaleState { .. })
    ));
    // Without the evidence it is not (the stated limit).
    assert!(rig.open(None).is_ok());
}

fn at(height: u64, block_id: Digest) -> ChainPoint {
    ChainPoint(height, block_id)
}

/// Halted at working height 8: height 7 certified with X, then a valid
/// certificate for 7 naming Y.
fn halted_real() -> (Rig, RealSigner) {
    let (rig, mut s) = locked();
    s.advance(&cert(4, 7, 0, X, &[0, 2, 3]).encode().unwrap())
        .unwrap();
    s.sign(&own(VoteType::Prevote, 8, 0, Some(Y))).unwrap();
    assert_eq!(
        s.advance(&cert(4, 7, 3, Y, &[0, 1, 3]).encode().unwrap()),
        Err(SignerError::ConflictingFinality(7))
    );
    (rig, s)
}

#[test]
fn recovery_refuses_insufficient_forged_wrong_fork_and_too_low_certificates() {
    let (rig, mut s) = halted_real();
    let before_all = rig.writes();
    let with = |f: fn(&mut FinalityCertificateV1)| {
        let mut c = cert(4, 9, 0, X, &[0, 1, 2]);
        f(&mut c);
        c.encode().unwrap()
    };
    let refused: Vec<(&str, Vec<u8>)> = vec![
        (
            "insufficient: k < q(n)",
            cert(4, 9, 0, X, &[0, 1]).encode().unwrap(),
        ),
        ("forged signature", with(|c| c.entries[0].signature[3] ^= 1)),
        // The other fork: its config commitment is not this node's.
        (
            "wrong fork (config commitment)",
            with(|c| c.consensus_config_commitment = [0xc1; 32]),
        ),
        (
            "wrong set commitment",
            with(|c| c.validator_set_commitment = valset_commitment(5)),
        ),
        (
            "a prevote quorum, not a certificate",
            polka(4, 9, 0, X, &[0, 1, 2]).encode().unwrap(),
        ),
        (
            "unknown height",
            cert(4, 99, 0, X, &[0, 1, 2]).encode().unwrap(),
        ),
    ];
    for (what, proof) in refused {
        let before = rig.writes();
        assert!(
            matches!(
                s.recover_after_conflict(&at(9, X), &proof, None),
                Err(SignerError::InvalidFinalityProof(_))
            ),
            "{what}"
        );
        assert_eq!(rig.writes(), before, "{what}: nothing written");
        assert!(s.is_halted(), "{what}");
    }
    for low in [6u64, 7] {
        assert!(matches!(
            s.recover_after_conflict(
                &at(low, X),
                &cert(4, low, 0, X, &[0, 1, 2]).encode().unwrap(),
                None
            ),
            Err(SignerError::RecoveryTooLow { working: 8, .. })
        ));
    }
    // Same validator set and configuration on both forks: a valid certificate
    // for the other fork's block at 9 is refused because the node follows X.
    assert!(matches!(
        s.recover_after_conflict(
            &at(9, X),
            &cert(4, 9, 0, Y, &[0, 1, 2]).encode().unwrap(),
            None
        ),
        Err(SignerError::RecoveryWrongFork { .. })
    ));
    assert_eq!(rig.writes(), before_all, "nothing written by any refusal");
    // Evidence supplied by the operator must be a verified conflicting certificate.
    let bad_evidence = cert(4, 7, 0, X, &[0, 2, 3]).encode().unwrap();
    assert!(matches!(
        s.recover_after_conflict(
            &at(9, X),
            &cert(4, 9, 0, X, &[0, 1, 2]).encode().unwrap(),
            Some(&bad_evidence)
        ),
        Err(SignerError::RecoveryEvidence(_))
    ));
    // A certificate at height 8 (the halted working height) on this node's
    // fork recovers; the floor is then 9.
    s.recover_after_conflict(
        &at(8, X),
        &cert(4, 8, 1, X, &[1, 2, 3]).encode().unwrap(),
        None,
    )
    .unwrap();
    assert!(!s.is_halted());
    assert_eq!(s.record().working_height(), Some(9));
    assert!(matches!(
        s.sign(&own(VoteType::Prevote, 8, 2, Some(X))),
        Err(SignerError::Regression { .. })
    ));
    s.sign(&own(VoteType::Prevote, 9, 0, Some(X))).unwrap();
    // The archived evidence is the conflicting certificate, trimmed to a quorum.
    let evidence = {
        let d = rig.disk.borrow();
        d.inodes[d.dir_vol["conflict-7.evidence"]].vol.clone()
    };
    let c = FinalityCertificateV1::decode(&evidence).unwrap();
    assert_eq!((c.height, c.block_id, c.entries.len()), (7, Y, 3));
}
