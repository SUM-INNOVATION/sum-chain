//! # BR1 beacon DKG + K-rotate W1b wire carriers (#125)
//!
//! Canonical byte codecs for the BR1 randomness-beacon carrier transactions:
//! [`RegisterBeaconKeyV1`] (K-rotate per-epoch encryption-key registration),
//! [`DkgDealV1`] (a single dealer→recipient scalar-share deal record), and
//! [`DkgComplaintV1`] (a DLEQ-authenticated complaint). These are the wire
//! encodings the BR1 security-design draft repeatedly labels `W1B-OWNED` and
//! defers to #125 (see the draft §8.7 "per-recipient ciphertext framing", §9.1
//! "the authenticated wire carrier", §5 DLEQ, §2.2 subgroup/infinity checks,
//! §11/§16.1 K-rotate, §16.3 ratification packet).
//!
//! ## Status: PRE-RATIFICATION — NOT CONSENSUS, NOT WIRED IN
//!
//! This module is **dormant wire plumbing only**. It is intentionally *not*
//! registered in [`crate::transaction::TxType`] / [`crate::transaction::TxPayload`],
//! so it is on **no** consensus, mempool, or block-application path and flips **no**
//! gate. It mirrors the B0-PRE family's stance ("no transaction ordinals; no
//! existing bytes change"). Two BR1 elements are RATIFIED by the owner (2026-07) —
//! `G_enc = BLS12-381 G1` and the K-rotate key lifecycle — and the codecs below
//! honour the byte consequences of those two (48-byte compressed G1 points;
//! per-epoch `RegisterBeaconKeyV1`). **Everything else** the carriers encode
//! (KDF/AEAD/DLEQ transcript details, threshold `T`, activation) is reviewer-
//! approved **PROPOSED**, not adopted; the encodings here MUST NOT be treated as
//! frozen consensus bytes until #125/#127 ratify them.
//!
//! ## Wire layer vs. crypto adapter boundary (deliberate)
//!
//! To keep this leaf crate free of any BLS/pairing dependency (per its charter),
//! group elements and field scalars are carried as **validated fixed-width byte
//! fields**, not as curve types:
//!
//! * **G1 points** (`EK_j`, `R_ij`, `D_ij`, Feldman commitments) — a fixed
//!   **48-byte** canonical-compressed (ZCash/`blst`) field. The decoder performs
//!   only the *cheap structural* checks that need no field arithmetic: the
//!   compression flag MUST be set and the infinity flag MUST be clear (rejecting
//!   the identity element the draft §2.2 forbids). **Full on-curve + prime-order
//!   subgroup membership validation is out of scope here and belongs to the #127
//!   crypto adapter** (`blst`/`arkworks`), which every consumer MUST run before use.
//! * **`F_r` scalars** (`dleq (c, z)`) — a fixed **32-byte little-endian** field
//!   with the mandatory canonical `< r` range check applied at decode (draft §5.6,
//!   §8.2). This check is exact and cheap (256-bit compare), so it lives here.
//! * **Proof-of-possession** — an **opaque fixed-width 96-byte** field (canonical
//!   compressed BLS12-381 **G2** signature, per draft §2.3 minimal-pubkey-size).
//!   Only its length is enforced here; `PopVerify` (subgroup, non-identity,
//!   pairing) is entirely #127's responsibility.
//!
//! ## Reject-trailing discipline
//!
//! The codecs reuse the crate's shared length-checked reader
//! ([`crate::b0::codec`]): every `decode` reads exactly its fields (truncation is a
//! decode error) and every `decode_exact` calls `Reader::finish` so a single
//! trailing byte — or a second concatenated record — is rejected. This is the same
//! strict discipline as [`crate::transaction::SignedTransaction::from_bytes`]'s
//! `reject_trailing_bytes` and the B0-PRE `decode_exact` family.

#![forbid(unsafe_code)]

use crate::b0::codec::{DecodeError, Reader, Writer};

// ---------------------------------------------------------------------------
// Fixed field widths (draft §5.6, §8.1, §8.2, §8.7, §2.3)
// ---------------------------------------------------------------------------

/// Canonical compressed BLS12-381 **G1** point width (bytes). RATIFIED
/// `G_enc = G1` fixes every encryption key / ephemeral / ECDH / commitment point
/// at this width (draft §5.6, §8.1).
pub const G1_LEN: usize = 48;

/// Canonical `F_r` scalar width (bytes), little-endian, mandatory `< r` (§5.6).
pub const SCALAR_LEN: usize = 32;

/// Proof-of-possession field width (bytes) — opaque canonical compressed
/// BLS12-381 **G2** signature (draft §2.3). Length-checked only at this layer.
pub const POP_LEN: usize = 96;

/// ECIES body width (bytes): 32-byte ChaCha20-Poly1305 ciphertext of the 32-byte
/// LE scalar share ‖ 16-byte Poly1305 tag (draft §8.2, §8.7). Fixed — a body of
/// any other length is a malformed deal.
pub const CT_LEN: usize = 48;

/// Number of Feldman commitments in a deal = polynomial `degree + 1 = T`.
///
/// PROPOSED (tracks #127 threshold `T = f + 1 = 2`, draft §1.2; "pending
/// adoption"). The deal decoder enforces exactly this many commitments, so this
/// constant is the single place the deal's fixed length depends on `T`. If #127
/// ratifies a different threshold, change it here (and [`DkgDealV1::LEN`]).
pub const DEGREE_PLUS_ONE: usize = 2;

/// First byte flag: compression bit — set in every canonical compressed encoding
/// (ZCash/`blst`). A field with it clear is not a compressed point.
const G1_COMPRESSION_FLAG: u8 = 0x80;
/// First byte flag: point-at-infinity bit. Set ⇒ the identity, rejected (§2.2).
const G1_INFINITY_FLAG: u8 = 0x40;

/// BLS12-381 scalar-field modulus `r`, **big-endian** (draft §1.1):
/// `0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001`.
const FR_MODULUS_BE: [u8; SCALAR_LEN] = [
    0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05,
    0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
];

/// True iff the little-endian 32-byte `s` is a canonical `F_r` scalar, i.e.
/// `s < r`. `s == r` and `s > r` are non-canonical and rejected (draft §5.6).
fn scalar_is_canonical(le: &[u8; SCALAR_LEN]) -> bool {
    // Compare most-significant byte first: le is little-endian, modulus is
    // big-endian, so `le[31 - i]` and `FR_MODULUS_BE[i]` are the same place value.
    for i in 0..SCALAR_LEN {
        let a = le[SCALAR_LEN - 1 - i];
        let b = FR_MODULUS_BE[i];
        if a < b {
            return true;
        }
        if a > b {
            return false;
        }
    }
    false // equal ⇒ not < r
}

/// Cheap structural check on a 48-byte compressed G1 field: the compression flag
/// is set and the infinity flag is clear (draft §2.2 non-identity). Does **not**
/// verify on-curve or subgroup membership — that is the #127 crypto adapter's job.
fn g1_structurally_ok(bytes: &[u8; G1_LEN]) -> bool {
    let flag = bytes[0];
    (flag & G1_COMPRESSION_FLAG) != 0 && (flag & G1_INFINITY_FLAG) == 0
}

/// Read a 48-byte G1 field and apply [`g1_structurally_ok`].
fn read_g1(r: &mut Reader, ctx: &'static str) -> Result<[u8; G1_LEN], DecodeError> {
    let p = r.read_array::<G1_LEN>(ctx)?;
    if !g1_structurally_ok(&p) {
        return Err(DecodeError::BadValue { ctx });
    }
    Ok(p)
}

/// Read a 32-byte scalar field and apply the canonical `< r` check.
fn read_scalar(r: &mut Reader, ctx: &'static str) -> Result<[u8; SCALAR_LEN], DecodeError> {
    let s = r.read_array::<SCALAR_LEN>(ctx)?;
    if !scalar_is_canonical(&s) {
        return Err(DecodeError::BadValue { ctx });
    }
    Ok(s)
}

// ---------------------------------------------------------------------------
// W1b operation ordinals (#125-proposed)
// ---------------------------------------------------------------------------

/// The W1b carrier operations, with their **#125-proposed** wire ordinals in the
/// [`crate::transaction::TxType`] ordinal space.
///
/// The BR1 draft earmarks tx ordinals 27/28/29 for these carriers and defers the
/// assignment to #125 (draft §9.1, §15 decision-table row "W1b tx ordinals
/// 28/29"). `TxType` currently occupies 0..=26 (`Supply = 26`), so 27/28/29 are
/// the next free values; the collision guard test asserts they are unused.
///
/// These ordinals are a **reservation** for a future #125 dispatch envelope. They
/// are **not** baked into the per-carrier bytes (each carrier self-domains via its
/// own 7-byte magic) and this enum is deliberately **not** wired into `TxType` /
/// `TxPayload`, keeping the family dormant / off the consensus path.
///
/// `DkgJustifyV1` is intentionally **absent**: the draft (§6.5/§6.6) makes the
/// dealer justification non-normative — the four objective verdicts are decided
/// from complaint evidence alone — so it is not part of the normative carrier set.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum BeaconWireOp {
    /// K-rotate per-epoch encryption-key registration ([`RegisterBeaconKeyV1`]).
    RegisterBeaconKey,
    /// DKG scalar-share deal record ([`DkgDealV1`]).
    DkgDeal,
    /// DLEQ-authenticated complaint ([`DkgComplaintV1`]).
    DkgComplaint,
}

impl BeaconWireOp {
    /// The #125-proposed wire ordinal for this operation.
    pub const fn to_repr(self) -> u8 {
        match self {
            BeaconWireOp::RegisterBeaconKey => 27,
            BeaconWireOp::DkgDeal => 28,
            BeaconWireOp::DkgComplaint => 29,
        }
    }

    /// Decode a wire ordinal, rejecting unknown values.
    pub fn from_repr(v: u8) -> Result<Self, DecodeError> {
        match v {
            27 => Ok(BeaconWireOp::RegisterBeaconKey),
            28 => Ok(BeaconWireOp::DkgDeal),
            29 => Ok(BeaconWireOp::DkgComplaint),
            _ => Err(DecodeError::BadEnum {
                name: "BeaconWireOp",
                value: v as u64,
            }),
        }
    }

    /// Every defined operation, for exhaustive testing.
    pub const ALL: &'static [BeaconWireOp] = &[
        BeaconWireOp::RegisterBeaconKey,
        BeaconWireOp::DkgDeal,
        BeaconWireOp::DkgComplaint,
    ];
}

// ---------------------------------------------------------------------------
// RegisterBeaconKeyV1 — K-rotate per-epoch encryption-key registration
// ---------------------------------------------------------------------------

/// K-rotate per-epoch encryption-key registration (draft §2.3, §11, §16.1).
///
/// Layout (`LEN` = 169 bytes):
/// `magic b"RBK1v1\0"[7] · schema_version u16 · chain_id u64_le · epoch u64_le ·
/// ek_j G1[48] · pop[96]`.
///
/// `ek_j` is the registrant's epoch-`e` encryption key `EK_j = g1^{ek_j}`; `pop`
/// is the opaque proof-of-possession (§2.3). The registrant identity and the
/// `(chain_id, validator, epoch)` keying (§11) are supplied by the future #125 tx
/// envelope's signer; this payload carries only `chain_id` + `epoch` + key + PoP.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisterBeaconKeyV1 {
    /// Chain id (replay separation), `u64_le`.
    pub chain_id: u64,
    /// Beacon epoch this key is registered for, `u64_le`.
    pub epoch: u64,
    /// `EK_j` — canonical compressed G1 (48B), non-identity (§2.2 structural).
    pub ek_j: [u8; G1_LEN],
    /// Opaque proof-of-possession (96B compressed G2 signature, §2.3).
    pub pop: [u8; POP_LEN],
}

impl RegisterBeaconKeyV1 {
    /// Seven-byte structure magic: `R B K 1 v 1 NUL`.
    pub const MAGIC: [u8; 7] = *b"RBK1v1\0";
    pub const SCHEMA_VERSION: u16 = 1;
    /// Documented total; asserted against the encoder-derived length in tests.
    pub const LEN: usize = 7 + 2 + 8 + 8 + G1_LEN + POP_LEN; // 169

    /// This carrier's #125-proposed wire ordinal.
    pub const fn wire_op() -> BeaconWireOp {
        BeaconWireOp::RegisterBeaconKey
    }

    /// Re-check the structural invariants a decoded value satisfies (G1 field of
    /// `ek_j`). Always `Ok` for a decoded value; exposed so callers can defend a
    /// hand-built value before [`try_encode`](Self::try_encode).
    pub fn validate(&self) -> Result<(), DecodeError> {
        if !g1_structurally_ok(&self.ek_j) {
            return Err(DecodeError::BadValue {
                ctx: "RegisterBeaconKeyV1.ek_j",
            });
        }
        Ok(())
    }

    /// Private raw serializer. Canonical only when [`validate`](Self::validate)
    /// holds; the public route is [`try_encode`](Self::try_encode).
    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(&Self::MAGIC);
        w.u16(Self::SCHEMA_VERSION);
        w.u64(self.chain_id);
        w.u64(self.epoch);
        w.bytes(&self.ek_j);
        w.bytes(&self.pop);
        w.into_bytes()
    }

    /// Canonical encode: validates the structural field invariants, then emits the
    /// fixed 169-byte layout. `Err` iff a field is structurally invalid.
    pub fn try_encode(&self) -> Result<Vec<u8>, DecodeError> {
        self.validate()?;
        Ok(self.encode())
    }

    /// Decode from a reader (truncation rejected; fields structurally validated).
    pub fn decode(r: &mut Reader) -> Result<Self, DecodeError> {
        let magic = r.read_array::<7>("RegisterBeaconKeyV1.magic")?;
        if magic != Self::MAGIC {
            return Err(DecodeError::BadTag {
                ctx: "RegisterBeaconKeyV1",
            });
        }
        let sv = r.read_u16("RegisterBeaconKeyV1.schema_version")?;
        if sv != Self::SCHEMA_VERSION {
            return Err(DecodeError::BadFixedScalar {
                ctx: "RegisterBeaconKeyV1.schema_version",
                value: sv as u64,
            });
        }
        let chain_id = r.read_u64("RegisterBeaconKeyV1.chain_id")?;
        let epoch = r.read_u64("RegisterBeaconKeyV1.epoch")?;
        let ek_j = read_g1(r, "RegisterBeaconKeyV1.ek_j")?;
        let pop = r.read_array::<POP_LEN>("RegisterBeaconKeyV1.pop")?;
        Ok(Self {
            chain_id,
            epoch,
            ek_j,
            pop,
        })
    }

    /// Decode consuming exactly `bytes` (rejects trailing).
    pub fn decode_exact(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let v = Self::decode(&mut r)?;
        r.finish("RegisterBeaconKeyV1")?;
        Ok(v)
    }
}

// ---------------------------------------------------------------------------
// DkgDealV1 — a single dealer→recipient scalar-share deal record
// ---------------------------------------------------------------------------

/// A single `(dealer i → recipient j)` DKG deal record (draft §8.2, §8.7, §9.1).
///
/// Layout (`LEN` = 229 bytes for `T = 2`):
/// `magic b"DKDLv1\0"[7] · schema_version u16 · chain_id u64_le · epoch u64_le ·
/// dealer_i u32_le · recipient_j u32_le · commitment_count u32_le ·
/// commitments (count × G1[48]) · r_ij G1[48] · ct_ij[48]`.
///
/// `commitments` are the dealer's Feldman commitments `C_{i,0..T-1}`
/// (`commitment_count` MUST equal [`DEGREE_PLUS_ONE`]); `r_ij` is the ECIES
/// ephemeral carrier `R_{ij} = g1^{r_ij}`; `ct_ij` is the fixed 48-byte
/// ChaCha20-Poly1305 body (32-byte scalar ciphertext ‖ 16-byte tag, §8.2/§8.7).
/// No nonce is transmitted (it is re-derived from the public context, §8.3).
/// Indices `i`, `j` are 0-based membership-snapshot indices (§8.2), not the
/// evaluation point `x_j = j + 1`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DkgDealV1 {
    /// Chain id, `u64_le`.
    pub chain_id: u64,
    /// Beacon epoch, `u64_le`.
    pub epoch: u64,
    /// Dealer index `i`, 0-based, `u32_le`.
    pub dealer_i: u32,
    /// Recipient index `j`, 0-based, `u32_le`.
    pub recipient_j: u32,
    /// Feldman commitments `C_{i,0..T-1}`, each canonical compressed G1 (48B).
    /// Length MUST equal [`DEGREE_PLUS_ONE`].
    pub commitments: Vec<[u8; G1_LEN]>,
    /// `R_{ij}` — ECIES carrier, canonical compressed G1 (48B), non-identity.
    pub r_ij: [u8; G1_LEN],
    /// `ct_{ij}` — 48-byte ChaCha20-Poly1305 body (32 ciphertext ‖ 16 tag).
    pub ct_ij: [u8; CT_LEN],
}

impl DkgDealV1 {
    /// Seven-byte structure magic: `D K D L v 1 NUL`.
    pub const MAGIC: [u8; 7] = *b"DKDLv1\0";
    pub const SCHEMA_VERSION: u16 = 1;
    /// Documented total for the canonical `T = DEGREE_PLUS_ONE` deal.
    /// `= 7 + 2 + 8 + 8 + 4 + 4 + 4 (count) + T*48 + 48 (R) + 48 (ct)`.
    pub const LEN: usize = 7 + 2 + 8 + 8 + 4 + 4 + 4 + DEGREE_PLUS_ONE * G1_LEN + G1_LEN + CT_LEN;

    /// This carrier's #125-proposed wire ordinal.
    pub const fn wire_op() -> BeaconWireOp {
        BeaconWireOp::DkgDeal
    }

    /// Re-check invariants: exactly [`DEGREE_PLUS_ONE`] commitments, every
    /// commitment and `r_ij` a structurally valid non-identity compressed G1.
    pub fn validate(&self) -> Result<(), DecodeError> {
        if self.commitments.len() != DEGREE_PLUS_ONE {
            return Err(DecodeError::BadFixedScalar {
                ctx: "DkgDealV1.commitment_count",
                value: self.commitments.len() as u64,
            });
        }
        for c in &self.commitments {
            if !g1_structurally_ok(c) {
                return Err(DecodeError::BadValue {
                    ctx: "DkgDealV1.commitment",
                });
            }
        }
        if !g1_structurally_ok(&self.r_ij) {
            return Err(DecodeError::BadValue {
                ctx: "DkgDealV1.r_ij",
            });
        }
        Ok(())
    }

    /// Private raw serializer; public route is [`try_encode`](Self::try_encode).
    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(&Self::MAGIC);
        w.u16(Self::SCHEMA_VERSION);
        w.u64(self.chain_id);
        w.u64(self.epoch);
        w.u32(self.dealer_i);
        w.u32(self.recipient_j);
        w.u32(self.commitments.len() as u32);
        for c in &self.commitments {
            w.bytes(c);
        }
        w.bytes(&self.r_ij);
        w.bytes(&self.ct_ij);
        w.into_bytes()
    }

    /// Canonical encode: validates invariants then emits the layout. `Err` iff the
    /// commitment count is wrong or any G1 field is structurally invalid.
    pub fn try_encode(&self) -> Result<Vec<u8>, DecodeError> {
        self.validate()?;
        Ok(self.encode())
    }

    /// Decode from a reader. Enforces the exact commitment count, each G1 field's
    /// structural validity, and the fixed `ct_ij` width; truncation is rejected.
    pub fn decode(r: &mut Reader) -> Result<Self, DecodeError> {
        let magic = r.read_array::<7>("DkgDealV1.magic")?;
        if magic != Self::MAGIC {
            return Err(DecodeError::BadTag { ctx: "DkgDealV1" });
        }
        let sv = r.read_u16("DkgDealV1.schema_version")?;
        if sv != Self::SCHEMA_VERSION {
            return Err(DecodeError::BadFixedScalar {
                ctx: "DkgDealV1.schema_version",
                value: sv as u64,
            });
        }
        let chain_id = r.read_u64("DkgDealV1.chain_id")?;
        let epoch = r.read_u64("DkgDealV1.epoch")?;
        let dealer_i = r.read_u32("DkgDealV1.dealer_i")?;
        let recipient_j = r.read_u32("DkgDealV1.recipient_j")?;
        let count = r.read_u32("DkgDealV1.commitment_count")?;
        if count as usize != DEGREE_PLUS_ONE {
            return Err(DecodeError::BadFixedScalar {
                ctx: "DkgDealV1.commitment_count",
                value: count as u64,
            });
        }
        let mut commitments = Vec::with_capacity(DEGREE_PLUS_ONE);
        for _ in 0..DEGREE_PLUS_ONE {
            commitments.push(read_g1(r, "DkgDealV1.commitment")?);
        }
        let r_ij = read_g1(r, "DkgDealV1.r_ij")?;
        let ct_ij = r.read_array::<CT_LEN>("DkgDealV1.ct_ij")?;
        Ok(Self {
            chain_id,
            epoch,
            dealer_i,
            recipient_j,
            commitments,
            r_ij,
            ct_ij,
        })
    }

    /// Decode consuming exactly `bytes` (rejects trailing).
    pub fn decode_exact(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let v = Self::decode(&mut r)?;
        r.finish("DkgDealV1")?;
        Ok(v)
    }
}

// ---------------------------------------------------------------------------
// DkgComplaintV1 — DLEQ-authenticated complaint
// ---------------------------------------------------------------------------

/// A DLEQ-authenticated complaint against dealer `i`'s deal to recipient `j`
/// (draft §5, §6.1, §9.1).
///
/// Layout (`LEN` = 193 bytes):
/// `magic b"DKCPv1\0"[7] · schema_version u16 · chain_id u64_le · epoch u64_le ·
/// i u32_le · j u32_le · r_ij G1[48] · d_ij G1[48] · dleq_c scalar[32] ·
/// dleq_z scalar[32]`.
///
/// `r_ij` is the carrier from the deal; `d_ij` is the claimed ECDH secret
/// `D_{ij}` (§5.2); `(dleq_c, dleq_z)` is the compact Chaum-Pedersen proof `(c, z)`
/// (§5.4), each a canonical LE `F_r` scalar (`< r`, §5.6). Adjudication (§6.1) is a
/// pure function of these fields plus the on-chain deal/key — no dealer secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DkgComplaintV1 {
    /// Chain id, `u64_le`.
    pub chain_id: u64,
    /// Beacon epoch, `u64_le`.
    pub epoch: u64,
    /// Accused dealer index `i`, 0-based, `u32_le`.
    pub i: u32,
    /// Complainant/recipient index `j`, 0-based, `u32_le`.
    pub j: u32,
    /// `R_{ij}` — carrier, canonical compressed G1 (48B), non-identity.
    pub r_ij: [u8; G1_LEN],
    /// `D_{ij}` — claimed ECDH secret, canonical compressed G1 (48B), non-identity.
    pub d_ij: [u8; G1_LEN],
    /// DLEQ challenge `c`, canonical LE `F_r` scalar (32B, `< r`).
    pub dleq_c: [u8; SCALAR_LEN],
    /// DLEQ response `z`, canonical LE `F_r` scalar (32B, `< r`).
    pub dleq_z: [u8; SCALAR_LEN],
}

impl DkgComplaintV1 {
    /// Seven-byte structure magic: `D K C P v 1 NUL`.
    pub const MAGIC: [u8; 7] = *b"DKCPv1\0";
    pub const SCHEMA_VERSION: u16 = 1;
    /// Documented total; asserted against the encoder-derived length in tests.
    pub const LEN: usize = 7 + 2 + 8 + 8 + 4 + 4 + G1_LEN + G1_LEN + SCALAR_LEN + SCALAR_LEN; // 193

    /// This carrier's #125-proposed wire ordinal.
    pub const fn wire_op() -> BeaconWireOp {
        BeaconWireOp::DkgComplaint
    }

    /// Re-check invariants: `r_ij`/`d_ij` structurally valid non-identity
    /// compressed G1, and `dleq_c`/`dleq_z` canonical `F_r` scalars (`< r`).
    pub fn validate(&self) -> Result<(), DecodeError> {
        if !g1_structurally_ok(&self.r_ij) {
            return Err(DecodeError::BadValue {
                ctx: "DkgComplaintV1.r_ij",
            });
        }
        if !g1_structurally_ok(&self.d_ij) {
            return Err(DecodeError::BadValue {
                ctx: "DkgComplaintV1.d_ij",
            });
        }
        if !scalar_is_canonical(&self.dleq_c) {
            return Err(DecodeError::BadValue {
                ctx: "DkgComplaintV1.dleq_c",
            });
        }
        if !scalar_is_canonical(&self.dleq_z) {
            return Err(DecodeError::BadValue {
                ctx: "DkgComplaintV1.dleq_z",
            });
        }
        Ok(())
    }

    /// Private raw serializer; public route is [`try_encode`](Self::try_encode).
    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(&Self::MAGIC);
        w.u16(Self::SCHEMA_VERSION);
        w.u64(self.chain_id);
        w.u64(self.epoch);
        w.u32(self.i);
        w.u32(self.j);
        w.bytes(&self.r_ij);
        w.bytes(&self.d_ij);
        w.bytes(&self.dleq_c);
        w.bytes(&self.dleq_z);
        w.into_bytes()
    }

    /// Canonical encode: validates invariants then emits the fixed 193-byte layout.
    pub fn try_encode(&self) -> Result<Vec<u8>, DecodeError> {
        self.validate()?;
        Ok(self.encode())
    }

    /// Decode from a reader (truncation rejected; G1 + scalar fields validated).
    pub fn decode(r: &mut Reader) -> Result<Self, DecodeError> {
        let magic = r.read_array::<7>("DkgComplaintV1.magic")?;
        if magic != Self::MAGIC {
            return Err(DecodeError::BadTag {
                ctx: "DkgComplaintV1",
            });
        }
        let sv = r.read_u16("DkgComplaintV1.schema_version")?;
        if sv != Self::SCHEMA_VERSION {
            return Err(DecodeError::BadFixedScalar {
                ctx: "DkgComplaintV1.schema_version",
                value: sv as u64,
            });
        }
        let chain_id = r.read_u64("DkgComplaintV1.chain_id")?;
        let epoch = r.read_u64("DkgComplaintV1.epoch")?;
        let i = r.read_u32("DkgComplaintV1.i")?;
        let j = r.read_u32("DkgComplaintV1.j")?;
        let r_ij = read_g1(r, "DkgComplaintV1.r_ij")?;
        let d_ij = read_g1(r, "DkgComplaintV1.d_ij")?;
        let dleq_c = read_scalar(r, "DkgComplaintV1.dleq_c")?;
        let dleq_z = read_scalar(r, "DkgComplaintV1.dleq_z")?;
        Ok(Self {
            chain_id,
            epoch,
            i,
            j,
            r_ij,
            d_ij,
            dleq_c,
            dleq_z,
        })
    }

    /// Decode consuming exactly `bytes` (rejects trailing).
    pub fn decode_exact(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let v = Self::decode(&mut r)?;
        r.finish("DkgComplaintV1")?;
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Field-level helpers ------------------------------------------------

    /// A structurally-valid compressed-G1 placeholder: compression flag set,
    /// infinity flag clear, arbitrary tail. NOT a real curve point — the wire
    /// layer only enforces the two cheap flags (#127 does the rest).
    fn g1(byte: u8) -> [u8; G1_LEN] {
        let mut p = [byte; G1_LEN];
        p[0] = G1_COMPRESSION_FLAG; // compressed, non-infinity
        p
    }

    /// A canonical scalar (`< r`): all-tail bytes with a small, safe MSB.
    fn scalar(byte: u8) -> [u8; SCALAR_LEN] {
        let mut s = [byte; SCALAR_LEN];
        s[SCALAR_LEN - 1] = 0x00; // top LE byte 0 ⇒ well below r
        s
    }

    #[test]
    fn scalar_canonicality_boundaries() {
        // 0 is canonical.
        assert!(scalar_is_canonical(&[0u8; SCALAR_LEN]));
        // r - 1 is canonical (LE), r and r + 1 are not.
        let mut r_minus_1 = [0u8; SCALAR_LEN];
        for i in 0..SCALAR_LEN {
            r_minus_1[i] = FR_MODULUS_BE[SCALAR_LEN - 1 - i];
        }
        r_minus_1[0] -= 1; // LE least-significant byte 0x01 -> 0x00
        assert!(scalar_is_canonical(&r_minus_1));
        // r itself (LE) is rejected.
        let mut r_le = [0u8; SCALAR_LEN];
        for i in 0..SCALAR_LEN {
            r_le[i] = FR_MODULUS_BE[SCALAR_LEN - 1 - i];
        }
        assert!(!scalar_is_canonical(&r_le));
        // all-0xFF (way above r) rejected.
        assert!(!scalar_is_canonical(&[0xFFu8; SCALAR_LEN]));
    }

    #[test]
    fn g1_flag_checks() {
        assert!(g1_structurally_ok(&g1(0x11)));
        // compression flag clear -> rejected.
        let mut bad = g1(0x11);
        bad[0] = 0x00;
        assert!(!g1_structurally_ok(&bad));
        // infinity flag set -> rejected (identity).
        let mut inf = g1(0x11);
        inf[0] = G1_COMPRESSION_FLAG | G1_INFINITY_FLAG;
        assert!(!g1_structurally_ok(&inf));
    }

    #[test]
    fn wire_ops_reserved_and_distinct() {
        // Ordinals are 27/28/29 and round-trip.
        for &op in BeaconWireOp::ALL {
            assert_eq!(BeaconWireOp::from_repr(op.to_repr()).unwrap(), op);
        }
        assert_eq!(BeaconWireOp::RegisterBeaconKey.to_repr(), 27);
        assert_eq!(BeaconWireOp::DkgDeal.to_repr(), 28);
        assert_eq!(BeaconWireOp::DkgComplaint.to_repr(), 29);
        assert!(BeaconWireOp::from_repr(26).is_err());
        assert!(BeaconWireOp::from_repr(30).is_err());
    }

    #[test]
    fn wire_ordinals_do_not_collide_with_txtype() {
        // The reserved 27/28/29 slots must be unused in the live TxType space.
        use crate::transaction::TxType;
        for &op in BeaconWireOp::ALL {
            assert!(
                TxType::from_byte(op.to_repr()).is_none(),
                "W1b ordinal {} collides with an existing TxType",
                op.to_repr()
            );
        }
        // And 26 (Supply) is the current max, so 27 is the first free slot.
        assert!(TxType::from_byte(26).is_some());
        assert!(TxType::from_byte(27).is_none());
    }

    // --- RegisterBeaconKeyV1 -------------------------------------------------

    fn sample_key() -> RegisterBeaconKeyV1 {
        RegisterBeaconKeyV1 {
            chain_id: 0x0102_0304_0506_0708,
            epoch: 42,
            ek_j: g1(0x21),
            pop: [0x33; POP_LEN],
        }
    }

    #[test]
    fn register_key_len_and_roundtrip() {
        let k = sample_key();
        let bytes = k.try_encode().unwrap();
        assert_eq!(bytes.len(), RegisterBeaconKeyV1::LEN);
        assert_eq!(bytes.len(), 169);
        assert_eq!(RegisterBeaconKeyV1::decode_exact(&bytes).unwrap(), k);
        assert_eq!(
            RegisterBeaconKeyV1::wire_op(),
            BeaconWireOp::RegisterBeaconKey
        );
    }

    #[test]
    fn register_key_rejects_bad_magic_version_trailing_truncation() {
        let bytes = sample_key().try_encode().unwrap();

        let mut m = bytes.clone();
        m[0] ^= 0xFF;
        assert!(matches!(
            RegisterBeaconKeyV1::decode_exact(&m),
            Err(DecodeError::BadTag { .. })
        ));

        let mut v = bytes.clone();
        v[7..9].copy_from_slice(&2u16.to_le_bytes());
        assert!(matches!(
            RegisterBeaconKeyV1::decode_exact(&v),
            Err(DecodeError::BadFixedScalar {
                ctx: "RegisterBeaconKeyV1.schema_version",
                ..
            })
        ));

        assert!(matches!(
            RegisterBeaconKeyV1::decode_exact(&bytes[..bytes.len() - 1]),
            Err(DecodeError::Truncated { .. })
        ));

        let mut long = bytes.clone();
        long.push(0);
        assert!(matches!(
            RegisterBeaconKeyV1::decode_exact(&long),
            Err(DecodeError::TrailingBytes { .. })
        ));

        // A second full record concatenated is rejected (must not stop at first).
        let mut two = bytes.clone();
        two.extend_from_slice(&bytes);
        assert!(RegisterBeaconKeyV1::decode_exact(&two).is_err());
    }

    #[test]
    fn register_key_rejects_malformed_ek() {
        // ek_j at offset 7 + 2 + 8 + 8 = 25.
        let off = 25;
        let bytes = sample_key().try_encode().unwrap();

        // infinity flag set.
        let mut inf = bytes.clone();
        inf[off] = G1_COMPRESSION_FLAG | G1_INFINITY_FLAG;
        assert!(matches!(
            RegisterBeaconKeyV1::decode_exact(&inf),
            Err(DecodeError::BadValue {
                ctx: "RegisterBeaconKeyV1.ek_j"
            })
        ));
        // compression flag clear.
        let mut unc = bytes.clone();
        unc[off] = 0x00;
        assert!(matches!(
            RegisterBeaconKeyV1::decode_exact(&unc),
            Err(DecodeError::BadValue {
                ctx: "RegisterBeaconKeyV1.ek_j"
            })
        ));

        // try_encode also rejects an in-memory malformed key.
        let mut bad = sample_key();
        bad.ek_j[0] = 0x00;
        assert!(bad.try_encode().is_err());
    }

    // --- DkgDealV1 ----------------------------------------------------------

    fn sample_deal() -> DkgDealV1 {
        DkgDealV1 {
            chain_id: 7,
            epoch: 9,
            dealer_i: 1,
            recipient_j: 3,
            commitments: vec![g1(0x41), g1(0x42)],
            r_ij: g1(0x51),
            ct_ij: [0x60; CT_LEN],
        }
    }

    #[test]
    fn deal_len_and_roundtrip() {
        let d = sample_deal();
        let bytes = d.try_encode().unwrap();
        assert_eq!(bytes.len(), DkgDealV1::LEN);
        assert_eq!(bytes.len(), 229);
        assert_eq!(DkgDealV1::decode_exact(&bytes).unwrap(), d);
        assert_eq!(DkgDealV1::wire_op(), BeaconWireOp::DkgDeal);
    }

    #[test]
    fn deal_rejects_wrong_commitment_count() {
        // Encode with the correct count then corrupt the u32 count field.
        // count is at offset 7 + 2 + 8 + 8 + 4 + 4 = 33.
        let bytes = sample_deal().try_encode().unwrap();
        let mut wrong = bytes.clone();
        wrong[33..37].copy_from_slice(&3u32.to_le_bytes());
        assert!(matches!(
            DkgDealV1::decode_exact(&wrong),
            Err(DecodeError::BadFixedScalar {
                ctx: "DkgDealV1.commitment_count",
                value: 3
            })
        ));

        // try_encode rejects an in-memory deal with the wrong number of commitments.
        let mut too_few = sample_deal();
        too_few.commitments.pop();
        assert!(matches!(
            too_few.try_encode(),
            Err(DecodeError::BadFixedScalar {
                ctx: "DkgDealV1.commitment_count",
                value: 1
            })
        ));
    }

    #[test]
    fn deal_rejects_malformed_commitment_and_carrier() {
        let bytes = sample_deal().try_encode().unwrap();
        // first commitment at offset 37.
        let mut bad_c = bytes.clone();
        bad_c[37] = 0x00; // compression flag clear
        assert!(matches!(
            DkgDealV1::decode_exact(&bad_c),
            Err(DecodeError::BadValue {
                ctx: "DkgDealV1.commitment"
            })
        ));
        // r_ij at offset 37 + 2*48 = 133.
        let mut bad_r = bytes.clone();
        bad_r[133] = G1_COMPRESSION_FLAG | G1_INFINITY_FLAG;
        assert!(matches!(
            DkgDealV1::decode_exact(&bad_r),
            Err(DecodeError::BadValue {
                ctx: "DkgDealV1.r_ij"
            })
        ));
    }

    #[test]
    fn deal_rejects_trailing_and_truncation() {
        let bytes = sample_deal().try_encode().unwrap();
        assert!(matches!(
            DkgDealV1::decode_exact(&bytes[..bytes.len() - 1]),
            Err(DecodeError::Truncated { .. })
        ));
        let mut long = bytes;
        long.push(0);
        assert!(matches!(
            DkgDealV1::decode_exact(&long),
            Err(DecodeError::TrailingBytes { .. })
        ));
    }

    // --- DkgComplaintV1 -----------------------------------------------------

    fn sample_complaint() -> DkgComplaintV1 {
        DkgComplaintV1 {
            chain_id: 11,
            epoch: 13,
            i: 2,
            j: 4,
            r_ij: g1(0x71),
            d_ij: g1(0x72),
            dleq_c: scalar(0x01),
            dleq_z: scalar(0x02),
        }
    }

    #[test]
    fn complaint_len_and_roundtrip() {
        let c = sample_complaint();
        let bytes = c.try_encode().unwrap();
        assert_eq!(bytes.len(), DkgComplaintV1::LEN);
        assert_eq!(bytes.len(), 193);
        assert_eq!(DkgComplaintV1::decode_exact(&bytes).unwrap(), c);
        assert_eq!(DkgComplaintV1::wire_op(), BeaconWireOp::DkgComplaint);
    }

    #[test]
    fn complaint_rejects_non_canonical_scalar() {
        // dleq_c at offset 7 + 2 + 8 + 8 + 4 + 4 + 48 + 48 = 129.
        let off_c = 129;
        let bytes = sample_complaint().try_encode().unwrap();
        let mut bad = bytes.clone();
        // set dleq_c = all 0xFF (>= r) -> rejected.
        for b in bad.iter_mut().skip(off_c).take(SCALAR_LEN) {
            *b = 0xFF;
        }
        assert!(matches!(
            DkgComplaintV1::decode_exact(&bad),
            Err(DecodeError::BadValue {
                ctx: "DkgComplaintV1.dleq_c"
            })
        ));

        // dleq_z at offset 129 + 32 = 161.
        let off_z = 161;
        let mut bad_z = bytes;
        for b in bad_z.iter_mut().skip(off_z).take(SCALAR_LEN) {
            *b = 0xFF;
        }
        assert!(matches!(
            DkgComplaintV1::decode_exact(&bad_z),
            Err(DecodeError::BadValue {
                ctx: "DkgComplaintV1.dleq_z"
            })
        ));

        // try_encode rejects an in-memory non-canonical scalar.
        let mut m = sample_complaint();
        m.dleq_z = [0xFF; SCALAR_LEN];
        assert!(m.try_encode().is_err());
    }

    #[test]
    fn complaint_rejects_malformed_g1_magic_trailing_truncation() {
        let bytes = sample_complaint().try_encode().unwrap();

        // r_ij at offset 7 + 2 + 8 + 8 + 4 + 4 = 33.
        let mut bad_r = bytes.clone();
        bad_r[33] = 0x00;
        assert!(matches!(
            DkgComplaintV1::decode_exact(&bad_r),
            Err(DecodeError::BadValue {
                ctx: "DkgComplaintV1.r_ij"
            })
        ));

        let mut m = bytes.clone();
        m[0] ^= 0xFF;
        assert!(matches!(
            DkgComplaintV1::decode_exact(&m),
            Err(DecodeError::BadTag { .. })
        ));

        assert!(matches!(
            DkgComplaintV1::decode_exact(&bytes[..bytes.len() - 1]),
            Err(DecodeError::Truncated { .. })
        ));

        let mut long = bytes;
        long.push(0);
        assert!(matches!(
            DkgComplaintV1::decode_exact(&long),
            Err(DecodeError::TrailingBytes { .. })
        ));
    }

    // --- Cross-type: magics are distinct, records don't cross-decode ---------

    #[test]
    fn magics_are_distinct_and_records_do_not_cross_decode() {
        assert_ne!(RegisterBeaconKeyV1::MAGIC, DkgDealV1::MAGIC);
        assert_ne!(RegisterBeaconKeyV1::MAGIC, DkgComplaintV1::MAGIC);
        assert_ne!(DkgDealV1::MAGIC, DkgComplaintV1::MAGIC);

        let key_bytes = sample_key().try_encode().unwrap();
        assert!(DkgDealV1::decode_exact(&key_bytes).is_err());
        assert!(DkgComplaintV1::decode_exact(&key_bytes).is_err());
    }
}
