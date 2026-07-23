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
//! gate. It mirrors the B0-PRE / C1 family stance (C1 compute-pool likewise adds
//! "no `TxPayload` ordinal", `crates/state/src/compute_pool.rs`). Two BR1 elements
//! are RATIFIED by the owner (2026-07) — `G_enc = BLS12-381 G1` and the K-rotate
//! key lifecycle — and the codecs below honour the byte consequences of those two
//! (48-byte compressed G1 points; per-epoch `RegisterBeaconKeyV1`). **Everything
//! else** the carriers encode (KDF/AEAD/DLEQ transcript details, threshold `T`,
//! activation) is reviewer-approved **PROPOSED**, not adopted; the encodings here
//! MUST NOT be treated as frozen consensus bytes until #125/#127 ratify them. In
//! particular, `T` (the DKG threshold / commitment count) is **not** ratified, so
//! it is **not** frozen into the wire: the deal uses a **self-validating**
//! variable-length commitment vector (see [`DkgDealV1`]) — the decoder carries no
//! commitment-count ceiling, only a checked self-consistency + allocation guard.
//!
//! ## Top-level ordinal band (owner allocation, 2026-07) — reservation only
//!
//! The top-level `TxType` ordinal space above the live W1a range (`0..=26`,
//! `Supply = 26`) is allocated across dormant subsystems. W1b gets a **two-slot
//! band (28/29)**; the complete beacon operation inventory (below) is grouped into
//! those two slots by protocol phase:
//!
//! | Ordinal | Owner | Beacon family (phase) |
//! |---------|-------|-----------------------|
//! | `27` | **C1 / ComputePool (#130)** — [`C1_COMPUTE_POOL_TXTYPE_RESERVED`] | NOT the beacon; W1b must not take 27. |
//! | `28` | **W1b beacon** — [`W1B_BEACON_DKG_TXTYPE`] | DKG / **epoch-setup**: key registration, deal, complaint. |
//! | `29` | **W1b beacon** — [`W1B_BEACON_SIGN_TXTYPE`] | **signing / output**: per-round partials, finalization. |
//!
//! These are **documented reservations**, not registered `TxType`/`TxPayload`
//! variants — the family stays dormant. (This refines the older
//! `crates/sumchain-wire/README.md` "ordinal 27+ owned by W1b" note: the owner
//! carved `27` out for C1 and gave W1b the `28/29` band.)
//!
//! ## Complete beacon operation inventory (PROPOSED — OWNER DECISION)
//!
//! Enumerated from the BR1 draft (nothing invented). Only the K-rotate direction
//! and `G_enc = G1` are ratified; every carrier layout is PROPOSED. This module
//! **implements the three slot-28 setup carriers**; the slot-29 signing carriers
//! are inventoried and their sub-tags reserved, but are left to a future
//! #125/#127 revision (implementing an unratified layout now would be inventing
//! bytes).
//!
//! | Op / carrier | Carries | Draft § | Phase → slot | Sub-tag | Status here |
//! |---|---|---|---|---|---|
//! | [`RegisterBeaconKeyV1`] | `EK_j` G1[48] + PoP G2[96] | §2.3, §11, §16.1 | setup → 28 | `0xBE01` | **implemented** (K-rotate dir. ratified) |
//! | [`DkgDealV1`] | `C_{i,*}` G1[48]×(deg+1), `R_ij` G1[48], `ct_ij`[48] | §8, §9.1 | setup → 28 | `0xBE02` | **implemented** (PROPOSED) |
//! | [`DkgComplaintV1`] | `i,j`, `R_ij` G1[48], `D_ij` G1[48], `dleq(c,z)` 2×[32] | §5, §6, §9.1 | setup → 28 | `0xBE03` | **implemented** (PROPOSED) |
//! | `DkgJustifyV1` | (`r_ij` + Schnorr) | §6.5 | — | — | **ABSENT / non-normative** (not a carrier) |
//! | `BeaconPartialV1` | `epoch, round, j`, `sigma_j` G2[96] | §2.4, §4.3, §10, §12 | signing → 29 | `0xBE04` (reserved) | inventoried; **not implemented** (PROPOSED) |
//! | `BeaconFinalizeV1` | `epoch, round`, combined `Sigma_r` G2[96], selected-contributor witness | §4.3, §12 | signing → 29 | `0xBE05` (reserved) | inventoried; **not implemented** (PROPOSED) |
//! | DKG finalization (QUAL) | (no carrier) deterministic state transition | §4.2, §6.1 | setup → 28 | — | **not a carrier** — deterministic transition (see below) |
//! | Equivocation — conflicting deal | (no carrier) two conflicting on-chain `DkgDealV1` sharing `(chain_id,epoch,i,j)` | §8.4, §6.4 | setup → 28 | — | **inline-detected** (see condition below) |
//! | Equivocation — conflicting partial | (no carrier) two conflicting on-chain partials sharing `(epoch,round,j)` | §6.4 | signing → 29 | — | **inline-detected** (see condition below) |
//!
//! ### DKG finalization is a deterministic state transition, not a carrier
//!
//! **DKG finalization — determining the `QUAL` set at `h_cd` and, on success
//! (`|QUAL| ≥ Q_dkg`), the epoch group key `PK_E = Σ_{i∈QUAL} C_{i,0}` — is a
//! DETERMINISTIC STATE TRANSITION computed from the on-chain deals, complaints, and
//! adjudication verdicts, NOT a submitted transaction carrier.** Verified against
//! the BR1 draft: `QUAL` is "the set of dealers not disqualified by adjudicated
//! complaints" and adjudication is "a pure function of on-chain data" (§4.2, §6.1),
//! so every validator recomputes the identical `QUAL`/`PK_E` — there is no proposer
//! `finalize-DKG` message and no submitted result to authenticate. It therefore
//! correctly consumes **no** band slot. This is **distinct from** `BeaconFinalizeV1`
//! (slot 29), which *is* a carrier: that is the per-round **signing-phase** output
//! combine `Σ_r = ⊕ λ_k·σ_k` over verified partials (§4.3, §12) — a produced beacon
//! output, not the epoch-setup QUAL determination.
//!
//! ### Equivocation inline-detection — the explicit condition (not a free lunch)
//!
//! Objective misconduct (§6.4) — conflicting deals/partials, invalid PoP, false
//! accusation — is adjudicated from *existing on-chain records* (the two
//! conflicting messages, the registration PoP, the complaint), so BR1 needs **no**
//! separate "evidence submission" transaction (unlike staking's explicit
//! `DoubleSignEvidence`), and equivocation consumes **no** band slot — **but only
//! under this explicit condition:** inline detection is valid **iff BOTH conflicting
//! signed records are (a) available to execution — both reached the executing
//! validator's view of the chain — AND (b) retained as evidence** (kept in
//! revertible state, not pruned), so the adjudicator can compare them and attribute
//! the verdict. If either conflicting record is absent from execution's view or has
//! been discarded, the equivocation is *not* inline-detectable and a dedicated
//! evidence carrier would be required; this design assumes both records persist
//! within the epoch's retention window (cf. §10/§11.3).
//!
//! ## Two-level namespacing — beacon op tags are NOT `TxType` ordinals
//!
//! Each beacon message kind is a **beacon-family-local operation sub-tag**
//! ([`BeaconWireOp`]), explicitly namespaced so it can never masquerade as a
//! top-level transaction ordinal:
//!
//! * its canonical on-wire identity is each carrier's own **7-byte magic**
//!   (self-domaining, like the B0-PRE production types); and
//! * its compact numeric discriminant ([`BeaconWireOp::to_repr`]) lives in the
//!   **`0xBE__` beacon namespace** ([`BEACON_OP_NAMESPACE`]) — a `u16` whose high
//!   byte is `0xBE`, which is unmistakably **not** a `u8` `TxType` ordinal
//!   (`0..=26`) nor a reserved band slot (`27`/`28`/`29`).
//!
//! Each op declares which reserved top-level band slot would carry it via
//! [`BeaconWireOp::top_level_txtype`]. The three implemented setup ops map to slot
//! 28; the reserved signing ops (partial/finalize) map to slot 29.
//!
//! ## Wire layer vs. crypto adapter boundary (deliberate — enforced downstream)
//!
//! To keep this leaf crate free of any BLS/pairing dependency (per its charter),
//! group elements and field scalars are carried as **validated fixed-width byte
//! fields**, not as curve types:
//!
//! * **G1 points** (`EK_j`, `R_ij`, `D_ij`, Feldman commitments) — a fixed
//!   **48-byte** canonical-compressed (ZCash/`blst`) field. The decoder performs
//!   only the *cheap structural* checks that need no field arithmetic: the
//!   compression flag MUST be set and the infinity flag MUST be clear (rejecting
//!   the identity element the draft §2.2 forbids).
//! * **`F_r` scalars** (`dleq (c, z)`) — a fixed **32-byte little-endian** field
//!   with the mandatory canonical `< r` range check applied at decode (draft §5.6,
//!   §8.2). This check is exact and cheap (256-bit compare), so it lives here.
//! * **Proof-of-possession** — an **opaque fixed-width 96-byte** field (canonical
//!   compressed BLS12-381 **G2** signature, per draft §2.3 minimal-pubkey-size).
//!   Only its length is enforced here.
//!
//! **LAYER-BOUNDARY CAVEAT (owner).** This module performs *only* the cheap
//! structural byte checks above. **Full curve / prime-order subgroup / infinity /
//! `PopVerify` (pairing) validation lives in the #127 crypto adapter**
//! (`blst`/`arkworks`), and **every future dispatch/execution path that accepts
//! beacon state into consensus MUST invoke that verification BEFORE accepting the
//! state.** Passing `decode_exact` here is *necessary but not sufficient*: a value
//! that decodes cleanly may still be off-curve, off-subgroup, or a non-verifying
//! PoP. Treat wire-decode success as "well-framed bytes", never as "valid crypto".
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
/// BLS12-381 **G2** signature (draft §2.3). Length-checked only at this layer;
/// `PopVerify` is the #127 crypto adapter's job (see the layer-boundary caveat).
pub const POP_LEN: usize = 96;

/// ECIES body width (bytes): 32-byte ChaCha20-Poly1305 ciphertext of the 32-byte
/// LE scalar share ‖ 16-byte Poly1305 tag (draft §8.2, §8.7). Fixed — a body of
/// any other length is a malformed deal.
pub const CT_LEN: usize = 48;

// ---------------------------------------------------------------------------
// DkgDealV1 commitment-count bound — RESOLUTION A: self-validating decode
// ---------------------------------------------------------------------------
//
// This codec carries **no** canonical commitment-count ceiling. An earlier
// revision derived a `MAX_COMMITMENTS` from the genesis `max_block_bytes` default
// (`1_000_000`); that was **removed** — `max_block_bytes` is a *configurable*
// genesis parameter, not a hard protocol maximum, so deriving a wire-validity
// limit from its default would (again) couple valid chain configuration to the
// codec. There is likewise no `max_validators`-derived limit (semantic, also
// configurable).
//
// Instead, `DkgDealV1::decode` is a **prefix parser** (the crate convention — it
// reads exactly its own bytes and leaves trailing to `decode_exact`'s `finish`)
// that is **allocation-safe on two levels**: (1) with checked arithmetic and
// BEFORE reserving anything it verifies the remaining input holds AT LEAST
// `count * G1_LEN + (G1_LEN + CT_LEN)` bytes (commitment vector + fixed
// `r_ij`/`ct_ij` suffix), so a tiny buffer cannot declare a huge count and amplify
// an allocation — the count is bounded by the real input length; and (2) the
// reservation is FALLIBLE (`try_reserve_exact`, mapped to a `DecodeError`), so even
// a genuinely huge but well-framed buffer returns an error instead of aborting the
// process. The decoder imposes no count ceiling and deliberately does **not** encode
// `T`, the validator cap, or a block-size-derived ceiling.
//
// **SEMANTICS LIVE ABOVE THE WIRE (layer-boundary note, cf. the PoP caveat).**
// Wire-decode success means only "well-framed and internally self-consistent". A
// future dispatch/execution path MUST, before accepting a deal into state, enforce
// the semantic limits this codec deliberately omits, all evaluated at execution
// time:
//   * the **active** block-size limit — `GenesisParams::max_block_bytes` at that
//     height — applied to the **FULL serialized transaction envelope** (signature,
//     public key, nonce, fee, tx framing, …), NOT merely `BASE_LEN + commitments`;
//   * `commitment_count <= active StakingParams::max_validators`
//     (`crates/sumchain-wire/src/staking.rs`, enforced by
//     `crates/state/src/staking_executor.rs`); and
//   * `commitment_count == ratified T` (draft §1.2 `T = f + 1`, **unratified**).
//
// **RESOLUTION B (owner note — NOT implemented here).** The alternative is to
// ratify a genuine *hard protocol maximum* commitment count, independent of any
// configurable genesis default, whose derivation accounts for the complete
// transaction-envelope overhead (not just the deal body). That requires owner
// ratification; until then this module defaults to Resolution A above.

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

/// Fallibly reserve a commitment vector of `count` elements. Maps a
/// `TryReserveError` (allocation failure OR capacity overflow) to a
/// [`DecodeError::BadValue`] instead of aborting the process — protecting the
/// public [`DkgDealV1::decode`] codec even when a caller passes a genuinely huge
/// (well-framed) buffer whose declared count would exhaust memory. `DecodeError`
/// is the frozen b0 error type, so an allocation failure maps to its generic
/// `BadValue` (there is no dedicated allocation variant to add without editing the
/// frozen codec).
fn reserve_commitment_vec(count: usize) -> Result<Vec<[u8; G1_LEN]>, DecodeError> {
    let mut v: Vec<[u8; G1_LEN]> = Vec::new();
    v.try_reserve_exact(count)
        .map_err(|_| DecodeError::BadValue {
            ctx: "DkgDealV1.commitment_count_alloc",
        })?;
    Ok(v)
}

// ---------------------------------------------------------------------------
// Top-level ordinal-band reservations (owner allocation) — NOT registered
// ---------------------------------------------------------------------------

/// Top-level `TxType` ordinal `27` is owned by **C1 / ComputePool (#130)**, not
/// the beacon. Recorded here so the boundary is explicit and the beacon never
/// takes 27. (C1 itself is dormant and adds no live `TxType` variant — see
/// `crates/state/src/compute_pool.rs`.)
pub const C1_COMPUTE_POOL_TXTYPE_RESERVED: u8 = 27;

/// Reserved top-level `TxType` slot `28` for the beacon **DKG / epoch-setup**
/// family (W1b band). RESERVED, **not** registered in `TxType`/`TxPayload`
/// (dormant). Carries the epoch-setup ops [`RegisterBeaconKeyV1`], [`DkgDealV1`],
/// and [`DkgComplaintV1`], distinguished by their beacon-local op sub-tag /
/// 7-byte magic.
pub const W1B_BEACON_DKG_TXTYPE: u8 = 28;

/// Reserved top-level `TxType` slot `29` for the beacon **signing / output**
/// family (W1b band). RESERVED, **not** registered in `TxType`/`TxPayload`
/// (dormant). Will carry the per-round ops — beacon partial signatures
/// (`BeaconPartialV1`, sub-tag `0xBE04`) and finalization/combine
/// (`BeaconFinalizeV1`, sub-tag `0xBE05`); see the module-doc inventory. Those
/// carriers are PROPOSED and **not implemented in this module yet** — the slot and
/// their sub-tags are reserved for a future #125/#127 revision.
pub const W1B_BEACON_SIGN_TXTYPE: u8 = 29;

/// Namespace prefix (high byte `0xBE`, "BE"acon) for the beacon-local operation
/// sub-tag discriminants ([`BeaconWireOp::to_repr`]). A discriminant in this
/// namespace is a `u16 == 0xBE__`, which cannot be confused with a `u8` top-level
/// `TxType` ordinal (`0..=26`) or a reserved band slot (`27`/`28`/`29`).
pub const BEACON_OP_NAMESPACE: u16 = 0xBE00;

// Namespaced beacon-local op discriminants.
// Slot 28 (DKG / epoch-setup) — implemented in this module:
const OP_REGISTER_BEACON_KEY: u16 = BEACON_OP_NAMESPACE | 0x01;
const OP_DKG_DEAL: u16 = BEACON_OP_NAMESPACE | 0x02;
const OP_DKG_COMPLAINT: u16 = BEACON_OP_NAMESPACE | 0x03;
// Slot 29 (signing / output) — RESERVED for the PROPOSED, not-yet-implemented
// carriers: `BeaconPartialV1` = `0xBE04`, `BeaconFinalizeV1` = `0xBE05`.

/// The beacon-family-local operation sub-tags.
///
/// These are **not** top-level transaction ordinals. Their canonical on-wire
/// identity is each carrier's 7-byte magic ([`Self::magic`]); their compact
/// numeric form ([`Self::to_repr`]) is a namespaced `0xBE__` `u16`
/// ([`BEACON_OP_NAMESPACE`]). Each op reports which reserved top-level band slot
/// (28 / 29) would carry it ([`Self::top_level_txtype`]).
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
    /// The namespaced (`0xBE__`) beacon-local discriminant. NOT a `TxType` ordinal.
    pub const fn to_repr(self) -> u16 {
        match self {
            BeaconWireOp::RegisterBeaconKey => OP_REGISTER_BEACON_KEY,
            BeaconWireOp::DkgDeal => OP_DKG_DEAL,
            BeaconWireOp::DkgComplaint => OP_DKG_COMPLAINT,
        }
    }

    /// Decode a namespaced beacon-local discriminant, rejecting anything outside
    /// the `0xBE__` namespace and any unknown local op.
    pub fn from_repr(v: u16) -> Result<Self, DecodeError> {
        match v {
            OP_REGISTER_BEACON_KEY => Ok(BeaconWireOp::RegisterBeaconKey),
            OP_DKG_DEAL => Ok(BeaconWireOp::DkgDeal),
            OP_DKG_COMPLAINT => Ok(BeaconWireOp::DkgComplaint),
            _ => Err(DecodeError::BadEnum {
                name: "BeaconWireOp",
                value: v as u64,
            }),
        }
    }

    /// The carrier's canonical 7-byte self-domaining magic (its true wire
    /// identity — the numeric [`Self::to_repr`] is only a compact index).
    pub const fn magic(self) -> [u8; 7] {
        match self {
            BeaconWireOp::RegisterBeaconKey => RegisterBeaconKeyV1::MAGIC,
            BeaconWireOp::DkgDeal => DkgDealV1::MAGIC,
            BeaconWireOp::DkgComplaint => DkgComplaintV1::MAGIC,
        }
    }

    /// The reserved top-level `TxType` band slot that would carry this op. All
    /// three implemented ops are DKG / epoch-setup, so they map to slot `28`
    /// ([`W1B_BEACON_DKG_TXTYPE`]); the signing/output slot `29`
    /// ([`W1B_BEACON_SIGN_TXTYPE`]) is reserved for the not-yet-implemented
    /// partial/finalize carriers. (Reservation only — the family is not registered
    /// in `TxType`/`TxPayload`.)
    pub const fn top_level_txtype(self) -> u8 {
        match self {
            BeaconWireOp::RegisterBeaconKey
            | BeaconWireOp::DkgDeal
            | BeaconWireOp::DkgComplaint => W1B_BEACON_DKG_TXTYPE,
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

    /// This carrier's beacon-local op sub-tag.
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
/// Layout (variable, `encoded_len(count)` bytes):
/// `magic b"DKDLv1\0"[7] · schema_version u16 · chain_id u64_le · epoch u64_le ·
/// dealer_i u32_le · recipient_j u32_le · commitment_count u32_le ·
/// commitments (count × G1[48]) · r_ij G1[48] · ct_ij[48]`.
///
/// `commitments` are the dealer's Feldman commitments `C_{i,0..T-1}`. Because the
/// threshold `T` is **not** owner-ratified (draft §1.2, PROPOSED), it is not
/// frozen into the wire: the count is a `u32_le` length prefix and the decoder is
/// **self-validating** — it carries no count ceiling; it only requires (via checked
/// arithmetic, before allocating) that the declared count exactly accounts for the
/// remaining input (see [`decode`](Self::decode)). The record length is a function
/// of the declared count, not a fixed constant.
///
/// `r_ij` is the ECIES ephemeral carrier `R_{ij} = g1^{r_ij}`; `ct_ij` is the
/// fixed 48-byte ChaCha20-Poly1305 body (32-byte scalar ciphertext ‖ 16-byte tag,
/// §8.2/§8.7). No nonce is transmitted (it is re-derived from the public context,
/// §8.3). Indices `i`, `j` are 0-based membership-snapshot indices (§8.2), not the
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
    /// Length MUST be `>= 1`; the wire imposes no upper ceiling (the decoder's
    /// self-consistency check bounds it to what the input actually holds).
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
    /// Fixed overhead of a deal excluding the commitment vector:
    /// `7 (magic) + 2 (ver) + 8 (chain_id) + 8 (epoch) + 4 (i) + 4 (j) +
    /// 4 (count) + 48 (r_ij) + 48 (ct_ij)`.
    pub const BASE_LEN: usize = 7 + 2 + 8 + 8 + 4 + 4 + 4 + G1_LEN + CT_LEN; // 133

    /// Encoded length of a deal carrying `commitment_count` commitments.
    pub const fn encoded_len(commitment_count: usize) -> usize {
        Self::BASE_LEN + commitment_count * G1_LEN
    }

    /// This carrier's beacon-local op sub-tag.
    pub const fn wire_op() -> BeaconWireOp {
        BeaconWireOp::DkgDeal
    }

    /// Re-check invariants: `commitments.len() >= 1`, and every commitment and
    /// `r_ij` a structurally valid non-identity compressed G1. There is no upper
    /// count ceiling (see the module note): the wire codec carries none, and a
    /// decoded value's count is bounded by its own byte length.
    pub fn validate(&self) -> Result<(), DecodeError> {
        let n = self.commitments.len();
        if n == 0 {
            return Err(DecodeError::BadValue {
                ctx: "DkgDealV1.commitment_count_zero",
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
    /// commitment vector is empty or any G1 field is structurally invalid.
    pub fn try_encode(&self) -> Result<Vec<u8>, DecodeError> {
        self.validate()?;
        Ok(self.encode())
    }

    /// Decode from a reader — a **prefix parser** (crate convention), allocation-safe.
    ///
    /// Like every other `sumchain-wire` `decode` (e.g. the b0
    /// [`OutputManifestV1::decode`](crate::b0::manifest::OutputManifestV1::decode)
    /// and [`RegisterBeaconKeyV1::decode`]/[`DkgComplaintV1::decode`] in this
    /// module), this reads **exactly its own bytes and leaves any trailing bytes
    /// for the caller**; trailing-byte rejection is owned by
    /// [`decode_exact`](Self::decode_exact) via `Reader::finish`.
    ///
    /// After the fixed header it reads the `u32` count and, with **checked
    /// arithmetic and before allocating anything**, verifies the remaining input
    /// holds **at least** `count * G1_LEN + (G1_LEN + CT_LEN)` bytes — the
    /// commitment vector plus the fixed `r_ij`/`ct_ij` suffix. A tiny buffer
    /// declaring a huge count is therefore rejected (`Truncated`, or `BadValue` on
    /// `checked_mul` overflow) **before** any reservation. The count is then bounded
    /// by the real input length, and the reservation itself is **fallible**
    /// ([`try_reserve_exact`], mapped to `BadValue`) so even a genuinely huge but
    /// well-framed buffer returns a decode error instead of aborting the process.
    /// The decoder imposes no count ceiling.
    ///
    /// [`try_reserve_exact`]: Vec::try_reserve_exact
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
        if count == 0 {
            return Err(DecodeError::BadValue {
                ctx: "DkgDealV1.commitment_count_zero",
            });
        }
        // Minimum-length check (checked arithmetic), BEFORE allocating. Prefix
        // parser: this only verifies the deal's OWN bytes are present (`>=`); it
        // does NOT reject trailing bytes (that is `decode_exact`'s `finish`).
        // `checked_mul` guards overflow (matters on 32-bit `usize`); the `>=` guards
        // a tiny buffer from declaring a huge count, so the reservation below is
        // bounded by the real input length and can never be amplified.
        let commit_bytes = (count as usize)
            .checked_mul(G1_LEN)
            .ok_or(DecodeError::BadValue {
                ctx: "DkgDealV1.commitment_count_overflow",
            })?;
        let needed = commit_bytes
            .checked_add(G1_LEN + CT_LEN)
            .ok_or(DecodeError::BadValue {
                ctx: "DkgDealV1.commitment_count_overflow",
            })?;
        if r.remaining() < needed {
            return Err(DecodeError::Truncated {
                needed,
                remaining: r.remaining(),
                ctx: "DkgDealV1.commitments",
            });
        }
        // Fallible reservation: an over-large (but well-framed) count returns a
        // decode error rather than aborting the process on `with_capacity`.
        let mut commitments = reserve_commitment_vec(count as usize)?;
        for _ in 0..count {
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

    /// Decode consuming exactly `bytes` (rejects trailing / count-vs-length
    /// mismatch: a buffer longer than the declared count implies is rejected).
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

    /// This carrier's beacon-local op sub-tag.
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

    // --- Namespacing / ordinal-band reconciliation --------------------------

    #[test]
    fn beacon_op_tags_are_namespaced_not_txtype_ordinals() {
        // (a) Every beacon-local op sub-tag lives in the 0xBE__ namespace and so
        //     is NOT a u8 top-level TxType ordinal (0..=26) nor a reserved band
        //     slot (27/28/29). This is the real anti-collision guarantee — it is
        //     grounded in the namespacing, not in "TxType currently stops at 26".
        for &op in BeaconWireOp::ALL {
            let r = op.to_repr();
            assert_eq!(
                r & 0xFF00,
                BEACON_OP_NAMESPACE,
                "op {op:?} not in the 0xBE__ beacon namespace"
            );
            assert!(
                r > 0x00FF,
                "op repr {r:#06x} could be mistaken for a u8 TxType ordinal"
            );
            assert_eq!(BeaconWireOp::from_repr(r).unwrap(), op);
        }
        // (b) W1b never claims C1's slot 27; W1b owns exactly the 28/29 band
        //     (28 = DKG/setup, 29 = signing/output).
        assert_eq!(C1_COMPUTE_POOL_TXTYPE_RESERVED, 27);
        assert_eq!(W1B_BEACON_DKG_TXTYPE, 28);
        assert_eq!(W1B_BEACON_SIGN_TXTYPE, 29);
        assert_ne!(W1B_BEACON_DKG_TXTYPE, C1_COMPUTE_POOL_TXTYPE_RESERVED);
        assert_ne!(W1B_BEACON_SIGN_TXTYPE, C1_COMPUTE_POOL_TXTYPE_RESERVED);
        // (c) Each implemented op maps to a band slot in {28,29}, never C1's 27.
        //     All three current ops are epoch-setup, so they map to slot 28.
        for &op in BeaconWireOp::ALL {
            let t = op.top_level_txtype();
            assert!(t == W1B_BEACON_DKG_TXTYPE || t == W1B_BEACON_SIGN_TXTYPE);
            assert_ne!(t, C1_COMPUTE_POOL_TXTYPE_RESERVED);
        }
        assert_eq!(
            BeaconWireOp::RegisterBeaconKey.top_level_txtype(),
            W1B_BEACON_DKG_TXTYPE
        );
        assert_eq!(
            BeaconWireOp::DkgDeal.top_level_txtype(),
            W1B_BEACON_DKG_TXTYPE
        );
        assert_eq!(
            BeaconWireOp::DkgComplaint.top_level_txtype(),
            W1B_BEACON_DKG_TXTYPE
        );
        // (d) Namespaced-tag decode rejects values that look like TxType ordinals,
        //     the bare namespace, and unknown local ops.
        assert!(BeaconWireOp::from_repr(0x0001).is_err()); // a u8-range value
        assert!(BeaconWireOp::from_repr(27).is_err()); // C1's slot, not a beacon op
        assert!(BeaconWireOp::from_repr(28).is_err()); // band slot, not a beacon op
        assert!(BeaconWireOp::from_repr(BEACON_OP_NAMESPACE).is_err()); // no local op
        assert!(BeaconWireOp::from_repr(BEACON_OP_NAMESPACE | 0x04).is_err()); // unknown
                                                                               // (e) The op's canonical wire identity is its 7-byte magic.
        assert_eq!(
            BeaconWireOp::RegisterBeaconKey.magic(),
            RegisterBeaconKeyV1::MAGIC
        );
        assert_eq!(BeaconWireOp::DkgDeal.magic(), DkgDealV1::MAGIC);
        assert_eq!(BeaconWireOp::DkgComplaint.magic(), DkgComplaintV1::MAGIC);
    }

    #[test]
    fn beacon_band_is_dormant_not_registered_in_txtype() {
        // Dormancy check (NOT a collision check): the reserved band is not a live
        // TxType. C1's 27 is likewise dormant (C1 adds no live TxType variant).
        use crate::transaction::TxType;
        assert!(TxType::from_byte(C1_COMPUTE_POOL_TXTYPE_RESERVED).is_none());
        assert!(TxType::from_byte(W1B_BEACON_DKG_TXTYPE).is_none());
        assert!(TxType::from_byte(W1B_BEACON_SIGN_TXTYPE).is_none());
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

    // --- DkgDealV1 (bounded variable-length commitments) --------------------

    fn deal_with(count: usize) -> DkgDealV1 {
        DkgDealV1 {
            chain_id: 7,
            epoch: 9,
            dealer_i: 1,
            recipient_j: 3,
            commitments: (0..count).map(|k| g1(0x40 | (k as u8 & 0x0F))).collect(),
            r_ij: g1(0x51),
            ct_ij: [0x60; CT_LEN],
        }
    }

    #[test]
    fn deal_roundtrips_for_small_counts() {
        // No hard ceiling: the wire self-validates count against the payload.
        for count in [1usize, 2, 8, 64] {
            let d = deal_with(count);
            let bytes = d.try_encode().unwrap();
            assert_eq!(bytes.len(), DkgDealV1::encoded_len(count));
            assert_eq!(DkgDealV1::decode_exact(&bytes).unwrap(), d);
        }
        // The old fixed T=2 length is now just encoded_len(2) — no frozen constant.
        assert_eq!(DkgDealV1::encoded_len(2), 229);
        assert_eq!(DkgDealV1::encoded_len(1), DkgDealV1::BASE_LEN + G1_LEN);
        assert_eq!(DkgDealV1::wire_op(), BeaconWireOp::DkgDeal);
    }

    #[test]
    fn deal_decode_is_prefix_parser_decode_exact_rejects_trailing() {
        // Crate convention: `decode` reads exactly its own bytes and LEAVES trailing
        // for the caller; `decode_exact` owns trailing-byte rejection via `finish`.
        let deal = deal_with(2);
        let mut bytes = deal.try_encode().unwrap();
        bytes.extend_from_slice(&[0xAB, 0xCD, 0xEF]); // 3 trailing bytes

        // `decode` succeeds on the prefix and leaves exactly the 3 trailing bytes.
        let mut r = Reader::new(&bytes);
        let decoded = DkgDealV1::decode(&mut r).expect("prefix decode must succeed");
        assert_eq!(decoded, deal);
        assert_eq!(r.remaining(), 3);

        // `decode_exact` rejects the same input's trailing bytes.
        assert!(matches!(
            DkgDealV1::decode_exact(&bytes),
            Err(DecodeError::TrailingBytes { .. })
        ));
    }

    #[test]
    fn deal_amplification_dos_guard_rejects_huge_count_on_tiny_buffer() {
        // The core DoS guard: a tiny buffer that declares a huge count must be
        // rejected by the checked minimum-length check BEFORE any reservation, so
        // the commitment vector can never be amplified. Take a real count=1 deal
        // (181 bytes) and rewrite only its count field to u32::MAX.
        let bytes = deal_with(1).try_encode().unwrap();
        assert_eq!(bytes.len(), DkgDealV1::encoded_len(1)); // small buffer
        let mut huge = bytes;
        huge[33..37].copy_from_slice(&u32::MAX.to_le_bytes());
        // `checked_mul` does not overflow on 64-bit usize (u32::MAX * 48 fits), so
        // the `>=` check fires: needed (~206 GB) > the tiny actual remaining ->
        // Truncated, before any reservation. (On a 32-bit target the same input
        // trips `checked_mul` -> BadValue overflow instead; both reject pre-alloc.)
        assert!(matches!(
            DkgDealV1::decode_exact(&huge),
            Err(DecodeError::Truncated {
                ctx: "DkgDealV1.commitments",
                ..
            })
        ));
    }

    #[test]
    fn deal_fallible_reservation_maps_alloc_failure_to_decode_error() {
        // The reservation helper maps a `TryReserveError` (here a capacity overflow
        // from an impossibly large count) to a DecodeError rather than aborting —
        // the public-codec protection independent of the length check above.
        assert!(matches!(
            reserve_commitment_vec(usize::MAX),
            Err(DecodeError::BadValue {
                ctx: "DkgDealV1.commitment_count_alloc"
            })
        ));
        // A sane count reserves successfully.
        assert!(reserve_commitment_vec(8).unwrap().capacity() >= 8);
    }

    #[test]
    fn deal_rejects_zero_count() {
        // Build a well-formed count=1 deal, then rewrite the count field to 0.
        // count u32 at offset 7 + 2 + 8 + 8 + 4 + 4 = 33.
        let bytes = deal_with(1).try_encode().unwrap();
        let mut zero = bytes;
        zero[33..37].copy_from_slice(&0u32.to_le_bytes());
        assert!(matches!(
            DkgDealV1::decode_exact(&zero),
            Err(DecodeError::BadValue {
                ctx: "DkgDealV1.commitment_count_zero"
            })
        ));
        // try_encode rejects an in-memory empty commitment vector.
        let mut empty = deal_with(1);
        empty.commitments.clear();
        assert!(matches!(
            empty.try_encode(),
            Err(DecodeError::BadValue {
                ctx: "DkgDealV1.commitment_count_zero"
            })
        ));
    }

    #[test]
    fn deal_rejects_count_too_large_and_too_small() {
        let bytes = deal_with(2).try_encode().unwrap();

        // too LARGE: count 2 -> 3. `needed` (3 commitments + suffix) exceeds the
        // remaining input -> Truncated, before any reservation.
        let mut too_large = bytes.clone();
        too_large[33..37].copy_from_slice(&3u32.to_le_bytes());
        assert!(matches!(
            DkgDealV1::decode_exact(&too_large),
            Err(DecodeError::Truncated {
                ctx: "DkgDealV1.commitments",
                ..
            })
        ));

        // too SMALL: count 2 -> 1. Prefix `decode` accepts it (reads a valid 1-
        // commitment deal) and leaves the surplus 48 bytes trailing; `decode_exact`
        // then rejects that surplus via `finish`.
        let mut too_small = bytes;
        too_small[33..37].copy_from_slice(&1u32.to_le_bytes());
        let mut r = Reader::new(&too_small);
        assert!(DkgDealV1::decode(&mut r).is_ok());
        assert_eq!(r.remaining(), G1_LEN); // one commitment's worth of surplus
        assert!(matches!(
            DkgDealV1::decode_exact(&too_small),
            Err(DecodeError::TrailingBytes { .. })
        ));
    }

    #[test]
    fn deal_rejects_malformed_commitment_and_carrier() {
        let d = deal_with(2);
        let bytes = d.try_encode().unwrap();
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
        let mut bad_r = bytes;
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
        let bytes = deal_with(2).try_encode().unwrap();

        // Trailing byte after a valid deal: `decode` consumes the prefix, leaving
        // one surplus byte; `decode_exact`'s `finish` rejects it -> TrailingBytes.
        let mut long = bytes.clone();
        long.push(0);
        assert!(matches!(
            DkgDealV1::decode_exact(&long),
            Err(DecodeError::TrailingBytes { .. })
        ));

        // One byte short (truncated in the ct_ij tail, after the count): the
        // remaining is one short of what the declared count needs -> the `>=`
        // minimum-length check fails = Truncated.
        assert!(matches!(
            DkgDealV1::decode_exact(&bytes[..bytes.len() - 1]),
            Err(DecodeError::Truncated {
                ctx: "DkgDealV1.commitments",
                ..
            })
        ));

        // Truncated inside the FIXED header (before the count is even read) -> the
        // Reader runs out mid-field = Truncated.
        assert!(matches!(
            DkgDealV1::decode_exact(&bytes[..20]),
            Err(DecodeError::Truncated { .. })
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
