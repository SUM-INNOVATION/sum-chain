//! Narrow BLS12-381 adapter for the BR1 beacon (issue #127).
//!
//! **All `blstrs`/`blst` usage is confined to this module.** Nothing here returns
//! or accepts a raw library type across the public boundary; callers see only the
//! opaque wrappers ([`G1Point`], [`Signature`], [`Pop`], [`PublicKey`],
//! [`PartialSignature`], [`SecretScalar`], [`DleqProof`]).
//!
//! Group placement follows the spec (§1.1, "minimal-pubkey-size"): **G1 public
//! keys / Feldman commitments / DLEQ elements, G2 signatures**. The ECIES/DLEQ
//! group `G_enc` is BLS12-381 G1 (owner-RATIFIED, §5.1), so DLEQ is single-group
//! Chaum-Pedersen over `F_r`.
//!
//! Ciphersuite DSTs are pinned per spec §2.1 (fixed by draft-irtf-cfrg-bls-
//! signature-05 / RFC 9380). [`DST_DLEQ`] is a #127 PROPOSED tag (§5.3), not
//! adopted consensus bytes.

use crate::hash_to_scalar::hash_to_scalar;
use crate::{BeaconCryptoError, Result};

use blstrs::{pairing, G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use ff::Field;
use group::{prime::PrimeCurveAffine, Curve, Group};
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Canonical compressed G1 element width (spec §5.6): 48 bytes.
pub const G1_COMPRESSED_SIZE: usize = 48;

/// Canonical compressed G2 element width: 96 bytes.
pub const G2_COMPRESSED_SIZE: usize = 96;

/// Canonical little-endian scalar width in `F_r`: 32 bytes.
pub const SCALAR_SIZE: usize = 32;

/// Reconstruction threshold `T = f + 1 = 2` (spec §1.2). The exactly-`T` combine
/// ([`combine`]) selects exactly this many partials.
pub const THRESHOLD_T: usize = 2;

/// Signing / partial-signature DST — draft-irtf-cfrg-bls-signature-05 §4.2.3 POP
/// ciphersuite, minimal-pubkey-size (spec §2.1). NORMATIVE (standard-fixed).
pub const DST_SIG: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// Proof-of-possession DST — draft-irtf-cfrg-bls-signature-05 §4.2.3 (spec §2.1).
/// NORMATIVE (standard-fixed).
pub const DST_POP: &[u8] = b"BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// DLEQ Fiat-Shamir domain tag (spec §5.3). **PROPOSED** (owner decision, not
/// adopted); the hash-to-scalar primitive is OPEN (§15 #22).
pub const DST_DLEQ: &[u8] = b"OMNINODE-DKG-DLEQ:v1:";

// ---------------------------------------------------------------------------
// G1 points (G_enc / verification-key group)
// ---------------------------------------------------------------------------

/// A validated BLS12-381 **G1** element (the ratified `G_enc`, and the group of
/// verification keys / Feldman commitments / DLEQ elements).
///
/// A `G1Point` can only be constructed via [`G1Point::from_compressed`] (which
/// enforces the spec §2.2 checks) or [`G1Point::generator`], so *holding* one is
/// a proof that it is canonical, on-curve, in the prime-order subgroup, and
/// **not** the identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct G1Point(G1Affine);

impl G1Point {
    /// Decode a canonical 48-byte compressed G1 point with the mandatory spec
    /// §2.2 checks: on-curve + prime-order subgroup + **infinity rejection**.
    ///
    /// `blstrs::G1Affine::from_compressed` already performs the on-curve and
    /// torsion-free (subgroup) checks and rejects non-canonical encodings; we
    /// additionally reject the identity, which that method accepts.
    pub fn from_compressed(bytes: &[u8; G1_COMPRESSED_SIZE]) -> Result<Self> {
        let affine: G1Affine = Option::from(G1Affine::from_compressed(bytes))
            .ok_or(BeaconCryptoError::InvalidPoint)?;
        if bool::from(affine.is_identity()) {
            return Err(BeaconCryptoError::PointAtInfinity);
        }
        Ok(G1Point(affine))
    }

    /// Canonical 48-byte compressed encoding.
    pub fn to_compressed(&self) -> [u8; G1_COMPRESSED_SIZE] {
        self.0.to_compressed()
    }

    /// The fixed generator `h = g1` (spec §5.1).
    pub fn generator() -> Self {
        G1Point(G1Affine::generator())
    }

    fn projective(&self) -> G1Projective {
        self.0.into()
    }
}

/// A beacon **verification key** `vk = g1^{sk}` in G1. Distinct wrapper from
/// [`G1Point`] for type-safety at the API boundary, but the same underlying
/// group and the same §2.2 validation (which is exactly `KeyValidate`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey(G1Affine);

impl PublicKey {
    /// Decode + `KeyValidate` (on-curve + subgroup + non-identity, spec §2.2/§2.3).
    pub fn from_compressed(bytes: &[u8; G1_COMPRESSED_SIZE]) -> Result<Self> {
        Ok(PublicKey(G1Point::from_compressed(bytes)?.0))
    }

    /// Canonical 48-byte compressed encoding.
    pub fn to_compressed(&self) -> [u8; G1_COMPRESSED_SIZE] {
        self.0.to_compressed()
    }
}

// ---------------------------------------------------------------------------
// G2 signatures / PoP
// ---------------------------------------------------------------------------

/// A validated BLS12-381 **G2** element (subgroup + non-identity checked), the
/// backing of [`Signature`] / [`Pop`] / [`PartialSignature`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct G2Point(G2Affine);

impl G2Point {
    fn from_compressed(bytes: &[u8; G2_COMPRESSED_SIZE]) -> Result<Self> {
        let affine: G2Affine = Option::from(G2Affine::from_compressed(bytes))
            .ok_or(BeaconCryptoError::InvalidPoint)?;
        if bool::from(affine.is_identity()) {
            return Err(BeaconCryptoError::PointAtInfinity);
        }
        Ok(G2Point(affine))
    }

    fn to_compressed(self) -> [u8; G2_COMPRESSED_SIZE] {
        self.0.to_compressed()
    }

    fn projective(&self) -> G2Projective {
        self.0.into()
    }
}

/// A BLS signature `sigma = H_{G2}(m)^{sk}` in G2 (spec §2.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signature(G2Point);

impl Signature {
    /// Decode a canonical 96-byte compressed signature (subgroup + non-identity).
    pub fn from_compressed(bytes: &[u8; G2_COMPRESSED_SIZE]) -> Result<Self> {
        Ok(Signature(G2Point::from_compressed(bytes)?))
    }

    /// Canonical 96-byte compressed encoding.
    pub fn to_compressed(&self) -> [u8; G2_COMPRESSED_SIZE] {
        self.0.to_compressed()
    }
}

/// A proof of possession `pop = H_{G2}(serialize(pk))^{sk}` in G2 (spec §2.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pop(G2Point);

impl Pop {
    /// Decode a canonical 96-byte compressed PoP (subgroup + non-identity).
    pub fn from_compressed(bytes: &[u8; G2_COMPRESSED_SIZE]) -> Result<Self> {
        Ok(Pop(G2Point::from_compressed(bytes)?))
    }

    /// Canonical 96-byte compressed encoding.
    pub fn to_compressed(&self) -> [u8; G2_COMPRESSED_SIZE] {
        self.0.to_compressed()
    }
}

/// A partial signature with its 1-based evaluation point `x_j = j + 1` (spec §3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PartialSignature {
    /// The evaluation point `x_j = j + 1` (never `0`).
    pub x: u64,
    sig: G2Point,
}

impl PartialSignature {
    /// Wrap a validated signature share at evaluation point `x = j + 1`.
    pub fn new(x: u64, sig: Signature) -> Self {
        PartialSignature { x, sig: sig.0 }
    }

    /// The underlying signature value.
    pub fn signature(&self) -> Signature {
        Signature(self.sig)
    }
}

// ---------------------------------------------------------------------------
// Secret scalars (signing keys / DLEQ witness)
// ---------------------------------------------------------------------------

/// A secret field element in `F_r` — a BLS signing share `sk_j`, a group secret,
/// or the DLEQ witness `ek_j`.
///
/// ## Zeroization
///
/// `blstrs::Scalar` is `Copy` and does **not** implement `Zeroize`, so it cannot
/// itself be reliably scrubbed. The **durable** secret is therefore held as its
/// canonical little-endian bytes inside [`Zeroizing`], which zeroes them on drop.
/// The `Scalar` is only materialised transiently inside [`SecretScalar::with_scalar`]
/// and best-effort overwritten before the scope ends. blst's scalar
/// multiplication is constant-time, so the group operations below do not branch
/// on secret bits.
#[derive(Clone)]
pub struct SecretScalar {
    le_bytes: Zeroizing<[u8; SCALAR_SIZE]>,
}

impl SecretScalar {
    /// Construct from canonical 32-byte little-endian bytes (rejects `>= r`).
    pub fn from_bytes_le(bytes: &[u8; SCALAR_SIZE]) -> Result<Self> {
        // Validate canonicalness up front; the value is reconstructed on demand.
        let _valid: Scalar = Option::from(Scalar::from_bytes_le(bytes))
            .ok_or(BeaconCryptoError::NonCanonicalScalar)?;
        Ok(SecretScalar {
            le_bytes: Zeroizing::new(*bytes),
        })
    }

    /// Run `f` with the materialised scalar, scrubbing the transient afterwards.
    fn with_scalar<R>(&self, f: impl FnOnce(&Scalar) -> R) -> R {
        // `le_bytes` was validated canonical at construction, so unwrap is safe.
        let mut scalar =
            Option::from(Scalar::from_bytes_le(&self.le_bytes)).expect("validated at construction");
        let out = f(&scalar);
        // Best-effort scrub of the transient (Scalar is Copy; not guaranteed, but
        // minimises secret-scalar lifetime — the durable copy is the Zeroizing bytes).
        scalar = Scalar::ZERO;
        let _ = core::hint::black_box(scalar);
        out
    }

    /// The public verification key `vk = g1^{sk}` (also the DLEQ `EK = h^{ek}`).
    pub fn public_key(&self) -> PublicKey {
        let p = self.with_scalar(|s| G1Projective::generator() * *s);
        PublicKey(p.to_affine())
    }

    /// The public G1 point `g1^{s}` as a [`G1Point`] (e.g. the DLEQ `EK_j`).
    pub fn public_g1(&self) -> G1Point {
        let p = self.with_scalar(|s| G1Projective::generator() * *s);
        G1Point(p.to_affine())
    }

    /// Sign `msg` (spec §2.4): `sigma = H_{G2}(msg; DST_SIG)^{sk}`.
    pub fn sign(&self, msg: &[u8]) -> Signature {
        let h = G2Projective::hash_to_curve(msg, DST_SIG, &[]);
        let p = self.with_scalar(|s| h * *s);
        Signature(G2Point(p.to_affine()))
    }

    /// Proof of possession (spec §2.3): `pop = H_{G2}(serialize(pk); DST_POP)^{sk}`.
    pub fn pop_prove(&self) -> Pop {
        let pk = self.public_key();
        let q = G2Projective::hash_to_curve(&pk.to_compressed(), DST_POP, &[]);
        let p = self.with_scalar(|s| q * *s);
        Pop(G2Point(p.to_affine()))
    }
}

// ---------------------------------------------------------------------------
// Verification (full signature, PoP, partial)
// ---------------------------------------------------------------------------

/// Verify a full BLS signature under `pk` (spec §2.4): `e(g1, sigma) == e(pk, H(m))`.
///
/// (`pk` is already `KeyValidate`d by construction; `sig` by decode.)
pub fn verify(pk: &PublicKey, msg: &[u8], sig: &Signature) -> bool {
    let h = G2Projective::hash_to_curve(msg, DST_SIG, &[]).to_affine();
    pairing_eq(&G1Affine::generator(), &sig.0 .0, &pk.0, &h)
}

/// Verify a proof of possession (spec §2.3): `e(g1, pop) == e(pk, Q)`,
/// `Q = H_{G2}(serialize(pk); DST_POP)`.
pub fn pop_verify(pk: &PublicKey, pop: &Pop) -> bool {
    let q = G2Projective::hash_to_curve(&pk.to_compressed(), DST_POP, &[]).to_affine();
    pairing_eq(&G1Affine::generator(), &pop.0 .0, &pk.0, &q)
}

/// Verify a partial signature under its per-participant verification key `vk_j`
/// (spec §2.4): `e(g1, sigma_j) == e(vk_j, H(m))`.
pub fn verify_partial(vk_j: &PublicKey, msg: &[u8], partial: &PartialSignature) -> bool {
    let h = G2Projective::hash_to_curve(msg, DST_SIG, &[]).to_affine();
    pairing_eq(&G1Affine::generator(), &partial.sig.0, &vk_j.0, &h)
}

/// Checks `e(a1, b1) == e(a2, b2)`. Spec §2.4 folds this into one multi-pairing
/// `e(g1, sigma) * e(-vk, H) == 1`; the two-pairing equality computed here is
/// value-identical and keeps the adapter free of extra pairing-trait plumbing.
fn pairing_eq(a1: &G1Affine, b1: &G2Affine, a2: &G1Affine, b2: &G2Affine) -> bool {
    pairing(a1, b1) == pairing(a2, b2)
}

// ---------------------------------------------------------------------------
// Exactly-T sorted Lagrange combine (in G2)
// ---------------------------------------------------------------------------

/// Exactly-`T` (`T = 2`) sorted Lagrange combination of partial signatures
/// (spec §4.3), interpolating at `x = 0`.
///
/// The caller MUST pass **already-verified** partials (spec §4.3 step 1: invalid
/// partials must never enter the interpolation — [`verify_partial`] is the gate).
/// This function then:
/// 1. sorts contributors ascending by `x_j`;
/// 2. rejects duplicate `x_j`;
/// 3. selects **exactly** the first `T` (errors if fewer than `T` are supplied);
/// 4. computes `lambda_k = prod_{l != k} x_l / (x_l - x_k) (mod r)` and returns
///    `Sigma = sum_k lambda_k * sigma_k` in G2.
pub fn combine(partials: &[PartialSignature]) -> Result<Signature> {
    if partials.len() < THRESHOLD_T {
        return Err(BeaconCryptoError::InsufficientPartials {
            need: THRESHOLD_T,
            got: partials.len(),
        });
    }

    // Sort ascending by x_j (canonical order, spec §4.1/§4.3).
    let mut sorted: Vec<PartialSignature> = partials.to_vec();
    sorted.sort_by_key(|p| p.x);

    // Reject duplicate evaluation points before selecting.
    for pair in sorted.windows(2) {
        if pair[0].x == pair[1].x {
            return Err(BeaconCryptoError::DuplicateEvaluationPoint(pair[0].x));
        }
    }

    // Select EXACTLY the first T (spec §4.3 step 3: |selection| = T, not >= T).
    let selection = &sorted[..THRESHOLD_T];
    let xs: Vec<Scalar> = selection.iter().map(|p| Scalar::from(p.x)).collect();

    let mut acc = G2Projective::identity();
    for (k, part) in selection.iter().enumerate() {
        // lambda_k = prod_{l != k} x_l / (x_l - x_k)
        let mut num = Scalar::ONE;
        let mut den = Scalar::ONE;
        for (l, x_l) in xs.iter().enumerate() {
            if l == k {
                continue;
            }
            num *= *x_l;
            den *= *x_l - xs[k];
        }
        let inv_den: Scalar = Option::from(den.invert())
            .ok_or(BeaconCryptoError::DuplicateEvaluationPoint(selection[k].x))?;
        let lambda = num * inv_den;
        acc += part.sig.projective() * lambda;
    }

    Ok(Signature(G2Point(acc.to_affine())))
}

// ---------------------------------------------------------------------------
// DKG aggregation, Feldman verification, ECDH (G1 arithmetic, spec §4.2/§6.2/§8)
// ---------------------------------------------------------------------------

impl PublicKey {
    /// Reinterpret a validated [`G1Point`] (same group, same §2.2 checks) as a
    /// beacon verification key. Used for the aggregated group key `PK_E` and the
    /// per-participant `vk_j`, which are sums of already-validated G1 elements.
    pub fn from_g1_point(p: G1Point) -> Self {
        PublicKey(p.0)
    }
}

impl SecretScalar {
    /// Sum two signing shares (spec §4.2): a participant's final share is
    /// `sk_j = Σ_{i∈QUAL} s_{ij}`. Field addition in `F_r`; the sum is always a
    /// canonical scalar, so this is infallible.
    pub fn add(&self, other: &SecretScalar) -> SecretScalar {
        let sum_le = self.with_scalar(|a| other.with_scalar(|b| (*a + *b).to_bytes_le()));
        SecretScalar {
            le_bytes: Zeroizing::new(sum_le),
        }
    }

    /// ECDH shared secret `D = point^{self}` in G1 (spec §8.2). For a dealer this is
    /// `D_{ij} = EK_j^{r_ij}`; for a recipient `D_{ij} = R_{ij}^{ek_j}`. Rejects an
    /// identity result (only possible from a zero scalar — a degenerate key).
    pub fn ecdh(&self, point: &G1Point) -> Result<G1Point> {
        let p = self.with_scalar(|s| point.projective() * *s).to_affine();
        if bool::from(p.is_identity()) {
            return Err(BeaconCryptoError::PointAtInfinity);
        }
        Ok(G1Point(p))
    }
}

/// Evaluate the *committed* polynomial "in the exponent" at `x`:
/// `Σ_{k} [x^k mod r] · C_k` (in G1), where `commitments = [C_0, …, C_{deg}]`.
/// This is the RHS of the Feldman check (spec §6.2) and a single dealer's
/// contribution term to the aggregated `vk_j` (spec §2.4/§4.2). `x = x_j = j + 1`
/// (spec §3). Returns `DegenerateAggregate` if `commitments` is empty or the term
/// evaluates to the identity.
pub fn commitment_poly_eval(commitments: &[G1Point], x: u64) -> Result<G1Point> {
    let acc = commitment_eval_projective(commitments, x)?;
    let aff = acc.to_affine();
    if bool::from(aff.is_identity()) {
        return Err(BeaconCryptoError::DegenerateAggregate);
    }
    Ok(G1Point(aff))
}

/// Internal: `Σ_k [x^k] C_k` in projective G1. Errors only on an empty vector.
fn commitment_eval_projective(commitments: &[G1Point], x: u64) -> Result<G1Projective> {
    if commitments.is_empty() {
        return Err(BeaconCryptoError::DegenerateAggregate);
    }
    let x = Scalar::from(x);
    let mut x_pow = Scalar::ONE; // x^0
    let mut acc = G1Projective::identity();
    for c in commitments {
        acc += c.projective() * x_pow;
        x_pow *= x;
    }
    Ok(acc)
}

/// Feldman share check (spec §6.2): `g1^{s} == Π_k C_k^{x^k}` (equivalently, in the
/// additive notation used here, `[s]·g1 == Σ_k [x^k] C_k`). `share_le` is the
/// candidate scalar share `s_ij` as canonical 32-byte little-endian; a non-canonical
/// (`≥ r`) encoding is rejected (`NonCanonicalScalar`). `x = x_j = j + 1`.
///
/// Returns `Ok(true)` iff the share is consistent with the dealer's commitments.
pub fn feldman_check(
    commitments: &[G1Point],
    x: u64,
    share_le: &[u8; SCALAR_SIZE],
) -> Result<bool> {
    let s: Scalar = Option::from(Scalar::from_bytes_le(share_le))
        .ok_or(BeaconCryptoError::NonCanonicalScalar)?;
    let lhs = G1Projective::generator() * s;
    let rhs = commitment_eval_projective(commitments, x)?;
    Ok(lhs == rhs)
}

/// Aggregate a set of validated G1 points into one (spec §4.2): `PK_E = Σ C_{i,0}`
/// over `QUAL`, or `vk_j = Σ_{i∈QUAL} (Σ_k [x_j^k] C_{i,k})`. Rejects an empty input
/// or a sum equal to the identity (a degenerate group/verification key, §2.2).
pub fn aggregate_g1(points: &[G1Point]) -> Result<G1Point> {
    if points.is_empty() {
        return Err(BeaconCryptoError::DegenerateAggregate);
    }
    let mut acc = G1Projective::identity();
    for p in points {
        acc += p.projective();
    }
    let aff = acc.to_affine();
    if bool::from(aff.is_identity()) {
        return Err(BeaconCryptoError::DegenerateAggregate);
    }
    Ok(G1Point(aff))
}

/// Whether canonical 32-byte little-endian `bytes` decode to an in-range `F_r`
/// scalar (`< r`). Confines the `blstrs::Scalar` canonicality test to this module so
/// the `ecies` module can range-check a decrypted share without touching `blstrs`.
pub(crate) fn scalar_le_is_canonical(bytes: &[u8; SCALAR_SIZE]) -> bool {
    Option::<Scalar>::from(Scalar::from_bytes_le(bytes)).is_some()
}

/// Evaluate a sharing polynomial `f(x) = Σ_k coeffs[k]·x^k` over `F_r` (spec §3),
/// returning the share `f(x)` as canonical 32-byte little-endian. Dealer-side share
/// computation: for recipient `j`, `x = x_j = j + 1`. Each coefficient must be a
/// canonical scalar (`< r`), else [`BeaconCryptoError::NonCanonicalScalar`].
pub fn eval_share_le(coeffs_le: &[[u8; SCALAR_SIZE]], x: u64) -> Result<[u8; SCALAR_SIZE]> {
    if coeffs_le.is_empty() {
        return Err(BeaconCryptoError::NonCanonicalScalar);
    }
    let x = Scalar::from(x);
    let mut x_pow = Scalar::ONE; // x^0
    let mut acc = Scalar::ZERO;
    for c in coeffs_le {
        let coeff: Scalar =
            Option::from(Scalar::from_bytes_le(c)).ok_or(BeaconCryptoError::NonCanonicalScalar)?;
        acc += coeff * x_pow;
        x_pow *= x;
    }
    Ok(acc.to_bytes_le())
}

// ---------------------------------------------------------------------------
// DLEQ (single-group Chaum-Pedersen in G1) — spec §5
// ---------------------------------------------------------------------------

/// Context bound into the DLEQ Fiat-Shamir transcript (spec §5.3) to prevent
/// cross-context replay: `(chain_id, epoch, dealer i, recipient j)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DleqContext {
    /// Chain identifier bytes.
    pub chain_id: Vec<u8>,
    /// DKG epoch.
    pub epoch: u64,
    /// Dealer index `i`.
    pub dealer_index: u32,
    /// Recipient index `j`.
    pub recipient_index: u32,
}

/// A compact Chaum-Pedersen DLEQ proof `(c, z)` (spec §5.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DleqProof {
    c: Scalar,
    z: Scalar,
}

impl DleqProof {
    /// Serialize as `c_le (32) || z_le (32)` = 64 bytes.
    pub fn to_bytes(&self) -> [u8; 2 * SCALAR_SIZE] {
        let mut out = [0u8; 2 * SCALAR_SIZE];
        out[..SCALAR_SIZE].copy_from_slice(&self.c.to_bytes_le());
        out[SCALAR_SIZE..].copy_from_slice(&self.z.to_bytes_le());
        out
    }

    /// Deserialize `c_le || z_le`, rejecting non-canonical scalars (`>= r`).
    pub fn from_bytes(bytes: &[u8; 2 * SCALAR_SIZE]) -> Result<Self> {
        let mut c_bytes = [0u8; SCALAR_SIZE];
        let mut z_bytes = [0u8; SCALAR_SIZE];
        c_bytes.copy_from_slice(&bytes[..SCALAR_SIZE]);
        z_bytes.copy_from_slice(&bytes[SCALAR_SIZE..]);
        let c: Scalar = Option::from(Scalar::from_bytes_le(&c_bytes))
            .ok_or(BeaconCryptoError::NonCanonicalScalar)?;
        let z: Scalar = Option::from(Scalar::from_bytes_le(&z_bytes))
            .ok_or(BeaconCryptoError::NonCanonicalScalar)?;
        Ok(DleqProof { c, z })
    }
}

/// Build the Fiat-Shamir transcript preimage exactly per spec §5.3:
///
/// ```text
/// DST_DLEQ ‖ chain_id ‖ u64_le(epoch) ‖ u32_le(i) ‖ u32_le(j)
///          ‖ ser(h) ‖ ser(EK) ‖ ser(R) ‖ ser(D) ‖ ser(A1) ‖ ser(A2)
/// ```
#[allow(clippy::too_many_arguments)]
fn dleq_transcript(
    ctx: &DleqContext,
    h: &G1Affine,
    ek: &G1Affine,
    r_ij: &G1Affine,
    d_ij: &G1Affine,
    a1: &G1Affine,
    a2: &G1Affine,
) -> Vec<u8> {
    let mut t = Vec::new();
    t.extend_from_slice(DST_DLEQ);
    t.extend_from_slice(&ctx.chain_id);
    t.extend_from_slice(&ctx.epoch.to_le_bytes());
    t.extend_from_slice(&ctx.dealer_index.to_le_bytes());
    t.extend_from_slice(&ctx.recipient_index.to_le_bytes());
    t.extend_from_slice(&h.to_compressed());
    t.extend_from_slice(&ek.to_compressed());
    t.extend_from_slice(&r_ij.to_compressed());
    t.extend_from_slice(&d_ij.to_compressed());
    t.extend_from_slice(&a1.to_compressed());
    t.extend_from_slice(&a2.to_compressed());
    t
}

/// DLEQ prover (spec §5.4). Proves `EK = h^{ek} AND D = R^{ek}` in zero knowledge.
///
/// `witness` is the secret `ek_j`; `nonce_k_le` is the fresh blinding scalar `k`
/// (a CSPRNG scalar in production; a fixed canonical value in the deterministic
/// vectors). `ek`, `r_ij`, `d_ij` are the public statement elements; `h` is the
/// generator (pass [`G1Point::generator`]).
///
/// Returns an error if `nonce_k_le` is non-canonical (`>= r`).
pub fn dleq_prove(
    ctx: &DleqContext,
    h: &G1Point,
    ek: &G1Point,
    r_ij: &G1Point,
    d_ij: &G1Point,
    witness: &SecretScalar,
    nonce_k_le: &[u8; SCALAR_SIZE],
) -> Result<DleqProof> {
    let mut k: Scalar = Option::from(Scalar::from_bytes_le(nonce_k_le))
        .ok_or(BeaconCryptoError::NonCanonicalScalar)?;

    // A1 = h^k, A2 = R^k
    let a1 = (h.projective() * k).to_affine();
    let a2 = (r_ij.projective() * k).to_affine();

    // c = HashToScalar(transcript(A1, A2))
    let transcript = dleq_transcript(ctx, &h.0, &ek.0, &r_ij.0, &d_ij.0, &a1, &a2);
    let c = hash_to_scalar(&transcript, DST_DLEQ);

    // z = k + c * ek (mod r)
    let z = witness.with_scalar(|ek_scalar| k + c * *ek_scalar);

    // Best-effort scrub the blinding scalar.
    k = Scalar::ZERO;
    let _ = core::hint::black_box(k);

    Ok(DleqProof { c, z })
}

/// DLEQ verifier (spec §5.5). Recomputes `A1' = h^z * EK^{-c}`,
/// `A2' = R^z * D^{-c}`, and accepts iff `HashToScalar(transcript(A1', A2')) == c`.
///
/// All four public G1 elements are already §2.2-validated by being [`G1Point`]s.
pub fn dleq_verify(
    ctx: &DleqContext,
    h: &G1Point,
    ek: &G1Point,
    r_ij: &G1Point,
    d_ij: &G1Point,
    proof: &DleqProof,
) -> bool {
    let neg_c = -proof.c;
    // A1' = h^z * EK^{-c}
    let a1 = (h.projective() * proof.z + ek.projective() * neg_c).to_affine();
    // A2' = R^z * D^{-c}
    let a2 = (r_ij.projective() * proof.z + d_ij.projective() * neg_c).to_affine();

    let transcript = dleq_transcript(ctx, &h.0, &ek.0, &r_ij.0, &d_ij.0, &a1, &a2);
    let c_prime = hash_to_scalar(&transcript, DST_DLEQ);
    c_prime == proof.c
}

// ---------------------------------------------------------------------------
// Test-only helpers (crafting adversarial inputs needs raw ops; kept in-crate).
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    /// Scalar-multiply an arbitrary G1 base by a secret scalar (for building DLEQ
    /// statement elements like `D_ij = R_ij^{ek}` in the vectors).
    pub(crate) fn g1_mul(base: &G1Point, s: &SecretScalar) -> G1Point {
        let p = s.with_scalar(|sc| base.projective() * *sc);
        G1Point(p.to_affine())
    }

    /// Evaluate a degree-1 polynomial `f(x) = a0 + a1*x` at `x` (in `F_r`),
    /// returning canonical little-endian bytes (for building DKG shares).
    pub(crate) fn poly_eval_deg1_le(a0: &[u8; 32], a1: &[u8; 32], x: u64) -> [u8; 32] {
        let a0 = Option::<Scalar>::from(Scalar::from_bytes_le(a0)).unwrap();
        let a1 = Option::<Scalar>::from(Scalar::from_bytes_le(a1)).unwrap();
        let y = a0 + a1 * Scalar::from(x);
        y.to_bytes_le()
    }

    /// Canonical compressed encoding of the G1 identity (point at infinity).
    pub(crate) fn g1_identity_compressed() -> [u8; G1_COMPRESSED_SIZE] {
        G1Affine::identity().to_compressed()
    }

    /// Deterministically craft a canonical, on-curve G1 point that is **not** in
    /// the prime-order subgroup (torsion / cofactor point). Returns its 48-byte
    /// compressed encoding. Used to prove the subgroup check rejects it.
    pub(crate) fn non_subgroup_g1_compressed() -> [u8; G1_COMPRESSED_SIZE] {
        // Search a deterministic sequence of compressed encodings for one that
        // decodes on-curve (via the unchecked path) but is NOT torsion-free.
        // A uniformly-chosen on-curve G1 point lies outside the order-r subgroup
        // with overwhelming probability (cofactor h1 is large), so this succeeds
        // almost immediately and deterministically.
        for seed in 0u64..100_000 {
            let mut bytes = [0u8; G1_COMPRESSED_SIZE];
            // Fill deterministically from the seed; set the compression bit (0x80)
            // and clear the infinity bit so the encoding is a compressed point.
            let s = seed.to_be_bytes();
            for (i, b) in bytes.iter_mut().enumerate() {
                *b = s[i % 8] ^ (i as u8).wrapping_mul(31);
            }
            bytes[0] = (bytes[0] & 0b0011_1111) | 0b1000_0000; // compressed, not-inf, sign from data

            if let Some(affine) =
                Option::<G1Affine>::from(G1Affine::from_compressed_unchecked(&bytes))
            {
                let on_curve = bool::from(affine.is_on_curve());
                let torsion_free = bool::from(affine.is_torsion_free());
                let identity = bool::from(affine.is_identity());
                if on_curve && !torsion_free && !identity {
                    return affine.to_compressed();
                }
            }
        }
        panic!("failed to construct a non-subgroup G1 point deterministically");
    }

    /// Assert the crafted bytes really are on-curve-but-not-subgroup under the
    /// unchecked decode (so the negative vector is meaningful).
    pub(crate) fn is_on_curve_but_not_subgroup(bytes: &[u8; G1_COMPRESSED_SIZE]) -> bool {
        match Option::<G1Affine>::from(G1Affine::from_compressed_unchecked(bytes)) {
            Some(affine) => {
                bool::from(affine.is_on_curve()) && !bool::from(affine.is_torsion_free())
            }
            None => false,
        }
    }
}
