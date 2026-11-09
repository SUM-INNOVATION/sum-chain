//! The production `Blake3StateHasher` (H = BLAKE3-256, ratified with the
//! 413-byte layout on 2026-10-22 and with the receipt on 2026-10-23; dormant,
//! nothing constructs it yet).
//!
//! * It equals the tests' BLAKE3 hasher (`common::B3`) on pseudo-random inputs
//!   of every length across the block and chunk boundaries, directly and
//!   through the crate's three digest functions.
//! * It reproduces the committed 413-byte KAT vectors
//!   (`tests/vectors/signer_state_413.json`): each checksum, each canonical
//!   re-encoding and each retained proof's digest and file name.
//! * It reproduces a 185-byte `RecoveryReceipt` known answer, computed
//!   independently with the stdlib BLAKE3 of
//!   `docs/proposals/g2-byte-review/generate.py`.

use serde_json::Value;
use sumchain_finality_foundations::signer_file::{
    offset, proof_digest, proof_file_name, sign_bytes_digest, Blake3StateHasher, ProofPurpose,
    RecoveryReceipt, SignerState, StateError, StateHasher, D_SIGNER, RECEIPT_LEN, STATE_LEN,
};
use sumchain_finality_foundations::Digest;

mod common;
use common::B3;

const H: Blake3StateHasher = Blake3StateHasher;

/// xorshift64*: reproducible inputs without a dependency.
struct Inputs(u64);

impl Inputs {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next() as u8).collect()
    }

    fn digest(&mut self) -> Digest {
        self.bytes(32).try_into().unwrap()
    }
}

#[test]
fn equals_the_test_hasher_on_random_inputs() {
    let mut inputs = Inputs(0x5eed_b1a4_e300_0001);
    // Every length up to two chunks and a bit, across the 64-byte block and
    // 1,024-byte chunk boundaries, then longer random lengths.
    let mut lengths: Vec<usize> = (0..=2_100).collect();
    lengths.extend((0..64).map(|_| (inputs.next() % 20_000) as usize));
    for len in lengths {
        let data = inputs.bytes(len);
        assert_eq!(H.hash(&data), B3.hash(&data), "length {len}");
        assert_eq!(
            sign_bytes_digest(&H, &data),
            sign_bytes_digest(&B3, &data),
            "sign-bytes digest, length {len}"
        );
        let purposes = [
            ProofPurpose::LockJustification {
                height: inputs.next(),
                round: (inputs.next() as u32) & 0xF_FFFF,
                value: inputs.digest(),
            },
            ProofPurpose::ConflictEvidence {
                height: inputs.next(),
                certified: inputs.digest(),
            },
            ProofPurpose::ResumeCertificate {
                height: inputs.next(),
                block: inputs.digest(),
            },
        ];
        for purpose in purposes {
            assert_eq!(
                proof_digest(&H, &purpose, &data),
                proof_digest(&B3, &purpose, &data),
                "proof digest {purpose:?}, length {len}"
            );
        }
    }
}

const STATE_VECTORS: &str = include_str!("vectors/signer_state_413.json");

struct StateVector {
    name: String,
    bytes: Vec<u8>,
    /// The retained proof's file name and bytes, if the record names one.
    proof: Option<(String, Vec<u8>)>,
}

fn state_vectors() -> Vec<StateVector> {
    let committed: Value = serde_json::from_str(STATE_VECTORS).expect("vectors are JSON");
    committed["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| StateVector {
            name: v["name"].as_str().unwrap().to_string(),
            bytes: hex::decode(v["hex"].as_str().unwrap()).unwrap(),
            proof: v["proof_hex"].as_str().map(|p| {
                (
                    v["proof_file"].as_str().unwrap().to_string(),
                    hex::decode(p).unwrap(),
                )
            }),
        })
        .collect()
}

#[test]
fn reproduces_the_413_byte_kat_vectors() {
    let vectors = state_vectors();
    assert_eq!(vectors.len(), 4, "the four committed vectors");
    let mut proofs = 0;
    for StateVector { name, bytes, proof } in vectors {
        assert_eq!(bytes.len(), STATE_LEN, "{name}");
        let mut preimage = D_SIGNER.to_vec();
        preimage.extend_from_slice(&bytes[..offset::CHECKSUM]);
        assert_eq!(
            H.hash(&preimage)[..],
            bytes[offset::CHECKSUM..],
            "{name}: checksum = BLAKE3-256(D_SIGNER ‖ bytes[0..381])"
        );
        let (state, checksum) = SignerState::decode(&bytes, &H).unwrap();
        assert_eq!(checksum[..], bytes[offset::CHECKSUM..], "{name}");
        assert_eq!(
            state.encode(&H).unwrap().to_vec(),
            bytes,
            "{name}: canonical"
        );
        assert_eq!(state.encode(&B3).unwrap().to_vec(), bytes, "{name}");

        let mut flipped = bytes.clone();
        flipped[offset::COUNTER] ^= 1;
        assert_eq!(
            SignerState::decode(&flipped, &H).unwrap_err(),
            StateError::Checksum,
            "{name}: a changed byte fails the checksum"
        );

        if let Some((file, proof)) = proof {
            proofs += 1;
            let digest = proof_digest(&H, &state.proof_purpose().unwrap(), &proof);
            assert_eq!(digest, state.proof_digest, "{name}: proof digest");
            assert_eq!(proof_file_name(&digest), file, "{name}: proof file");
        }
    }
    assert_eq!(proofs, 2, "the locked and the halted vector retain a proof");
}

/// Computed with the stdlib BLAKE3 of `docs/proposals/g2-byte-review/
/// generate.py`, not with the `blake3` crate. The halted checksum and the
/// evidence digest are those of the halted KAT vector (bytes 381..413 and
/// 317..349); the resume digest is BLAKE3-256(`D_PROOF` ‖ kind 3 context
/// (height 9, block `[0xC3; 32]`) ‖ the resume bytes below). Synthetic.
const RECEIPT_RESUME_BYTES: &[u8] = b"synthetic resume certificate, height 9";
const RECEIPT_RESUME_DIGEST: &str =
    "fef78bee93bb2c3cfa4d570505d44af898a3e0f99d887c9b61bd8090bf7a4713";
const RECEIPT_KAT: &str = "46524356763100010088c55091d622d3f8381a4ad6e73853212479872723e7d0\
     fd29224e026891bd2607000000000000000900000000000000c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3\
     c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3a09ee4327405ffd63686feeee58d554c0b3794547400d65ed7\
     746585190a6928fef78bee93bb2c3cfa4d570505d44af898a3e0f99d887c9b61bd8090bf7a471320ec\
     af26f4c85e2d27acfeba7b417ca761e5501ab5b28d27de5ca240c5aec9df";

#[test]
fn reproduces_the_recovery_receipt_known_answer() {
    let vectors = state_vectors();
    assert!(vectors[3].name.starts_with("halted"), "{}", vectors[3].name);
    let halted = &vectors[3].bytes;
    let d = |at: usize| -> Digest { halted[at..at + 32].try_into().unwrap() };
    let resume_block = [0xC3; 32];
    let resume_digest = proof_digest(
        &H,
        &ProofPurpose::ResumeCertificate {
            height: 9,
            block: resume_block,
        },
        RECEIPT_RESUME_BYTES,
    );
    assert_eq!(hex::encode(resume_digest), RECEIPT_RESUME_DIGEST);
    let receipt = RecoveryReceipt {
        halted_checksum: d(offset::CHECKSUM),
        conflict_height: 7,
        resume_height: 9,
        resume_block,
        evidence_digest: d(offset::PROOF),
        resume_digest,
    };

    let want = hex::decode(RECEIPT_KAT).unwrap();
    assert_eq!(want.len(), RECEIPT_LEN);
    let bytes = receipt.encode(&H);
    assert_eq!(
        hex::encode(bytes),
        RECEIPT_KAT,
        "the checksum is the reference's"
    );
    assert_eq!(receipt.encode(&B3), bytes);
    assert_eq!(RecoveryReceipt::decode(&want, &H).unwrap(), receipt);
    assert_eq!(RecoveryReceipt::decode(&want, &B3).unwrap(), receipt);

    let mut flipped = want.clone();
    flipped[41] ^= 1;
    assert_eq!(
        RecoveryReceipt::decode(&flipped, &H).unwrap_err(),
        StateError::Checksum,
        "a changed byte fails the checksum"
    );
}
