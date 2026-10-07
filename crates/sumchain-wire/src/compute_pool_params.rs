//! `ComputePoolParamsV1` — the C1 compute-pool parameter TYPE (issue #215).
//!
//! DORMANT. This module defines the ratified field list, its canonical
//! fixed-width encoding and its structural validation. It carries **no
//! values**: every field is supplied by the genesis that declares the surface
//! (`ChainParams::compute_pool_params`, absent by default), never by a
//! compiled default. Declaring the parameters does not open the compute-pool
//! gate; `compute_pool_enabled_from_height` stays refused at genesis load.
//!
//! ## Source of the field list
//!
//! The owner ratified the field list and order proposed in the #215 owner
//! decision packet (§4, checklist item 4), "minus `reservation` / `MARGIN`
//! pending definitions". Those two have no field here: their semantics are not
//! stated, and a field cannot be given to a value nobody has defined.
//!
//! ## Canonical encoding (`LEN` = 321 bytes, all integers little-endian)
//!
//! `MAGIC b"CPPRMv1"[7] · schema_version u16 = 1 · fields in the order below`.
//! The carrier convention is the frozen `beacon_wire` one (7-byte magic,
//! `u16` schema version, fixed-width LE, `decode_exact` refuses trailing
//! bytes). The encoding is FIXED-WIDTH: no length prefix, no optional field.
//!
//! | offset | field | type | group |
//! |---:|---|---|---|
//! | 0 | magic `CPPRMv1` | `[u8;7]` | |
//! | 7 | schema_version = 1 | u16 | |
//! | 9 | `b_offer` | u128 | 1 bonds |
//! | 25 | `b_commit` | u128 | 1 |
//! | 41 | `b_check` | u128 | 1 |
//! | 57 | `c_layer` | u64 | 2 cost weights |
//! | 65 | `c_tok` | u64 | 2 |
//! | 73 | `c_sel` | u64 | 2 |
//! | 81 | `c_emit` | u64 | 2 |
//! | 89 | `accept_reimb` | u128 | 3 reimbursements |
//! | 105 | `commit_verify_reimb` | u128 | 3 |
//! | 121 | `publish_reimb` | u128 | 3 |
//! | 137 | `observe_reimb` | u128 | 3 |
//! | 153 | `check_reimb` | u128 | 3 |
//! | 169 | `settle_reimb` | u128 | 3 |
//! | 185 | `reassign_reimb` | u128 | 3 |
//! | 201 | `max_work_units` | u64 | 4 capacity |
//! | 209 | `max_generations` | u64 | 4 |
//! | 217 | `max_reprovisionable_units` | u64 | 4 |
//! | 225 | `max_attempts_per_unit` | u32 | 5 |
//! | 229 | `max_reassignments_per_file` | u32 | 5 |
//! | 233 | `k_susp` | u64 | 6 suspension / invites |
//! | 241 | `w_susp` | u64 | 6 |
//! | 249 | `s_susp` | u64 | 6 |
//! | 257 | `n_invite_max` | u64 | 6 |
//! | 265 | `max_retention_files_per_job` | u64 | 7 retention (#129) |
//! | 273 | `max_retention_updates_per_block` | u64 | 7 |
//! | 281 | `max_reverse_index_entries` | u64 | 7 |
//! | 289 | `output_availability_blocks` | u64 | 7 |
//! | 297 | `d_avail` | u64 blocks | 8 deadlines (#133) |
//! | 305 | `d_ack` | u64 blocks | 8 |
//! | 313 | `d_final` | u64 blocks | 8 |
//! | 321 | end | | |
//!
//! Golden vectors: `tests/compute_pool_params_golden.rs` (append-only).
//!
//! ## Validation split (§G correction, #217 A7)
//!
//! [`ComputePoolParamsV1::validate`] is STRUCTURAL only, over `&self`, and
//! enforces exactly the rules packet §4 states — "non-zero caps,
//! `max_generations ≥ 1`, u128 sums checked":
//!
//! * every `max_*` field is non-zero (this includes `max_generations ≥ 1`);
//! * the u128 bond total `b_offer + b_commit + b_check` and the u128 total of
//!   the seven reimbursements do not overflow.
//!
//! §4 does not enumerate the caps or the sums. "Caps" is read as the eight
//! fields named `max_*`; `n_invite_max` and every other field may be zero.
//! The two sums are the only u128 groups in the type. Anything beyond this
//! (further caps, relations between fields) is an open owner decision. It
//! asserts no economic policy — a zero bond, zero reimbursement or zero cost
//! weight is structurally valid.
//! Checks that need chain context (registry entries, timelocks, head state,
//! the #129 retention relations) belong to the caller that has that context.
//!
//! ## Upgrade rule
//!
//! `ComputePoolParamsV1` is immutable once activated. A change is a `V2`
//! type with its own magic, schema version and activation height; V1 bytes
//! are never reinterpreted.

use serde::{Deserialize, Serialize};

use crate::b0::codec::{DecodeError, Reader, Writer};

/// The C1 compute-pool parameters, version 1. See the module docs for the
/// field order, the byte layout and what validation does and does not check.
///
/// Every field is required when the surface is declared: there is no
/// `#[serde(default)]` on any of them, because a default would be an invented
/// value. Unknown keys are refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComputePoolParamsV1 {
    // ── 1 · bonds ──
    /// `B_offer`, the bond posted with a bonded offer.
    pub b_offer: u128,
    /// `B_commit`.
    pub b_commit: u128,
    /// `B_check`.
    pub b_check: u128,
    // ── 2 · cost weights ──
    /// `C_layer`.
    pub c_layer: u64,
    /// `C_tok`.
    pub c_tok: u64,
    /// `C_sel`.
    pub c_sel: u64,
    /// `C_emit`.
    pub c_emit: u64,
    // ── 3 · reimbursements ──
    pub accept_reimb: u128,
    pub commit_verify_reimb: u128,
    pub publish_reimb: u128,
    pub observe_reimb: u128,
    pub check_reimb: u128,
    pub settle_reimb: u128,
    pub reassign_reimb: u128,
    // ── 4 · capacity / policy limits ──
    pub max_work_units: u64,
    pub max_generations: u64,
    pub max_reprovisionable_units: u64,
    // ── 5 ──
    pub max_attempts_per_unit: u32,
    pub max_reassignments_per_file: u32,
    // ── 6 · suspension / invites ──
    /// `K_susp`.
    pub k_susp: u64,
    /// `W_susp`.
    pub w_susp: u64,
    /// `S_susp`.
    pub s_susp: u64,
    /// `N_invite_max`.
    pub n_invite_max: u64,
    // ── 7 · retention (#129) ──
    pub max_retention_files_per_job: u64,
    pub max_retention_updates_per_block: u64,
    pub max_reverse_index_entries: u64,
    pub output_availability_blocks: u64,
    // ── 8 · deadlines in blocks (#133) ──
    pub d_avail: u64,
    pub d_ack: u64,
    pub d_final: u64,
}

impl ComputePoolParamsV1 {
    /// Seven-byte structure magic, as ratified: `C P P R M v 1` (no NUL).
    pub const MAGIC: [u8; 7] = *b"CPPRMv1";
    /// Encoding schema version.
    pub const SCHEMA_VERSION: u16 = 1;
    /// Exact encoded length; asserted against the encoder in tests.
    pub const LEN: usize = 7 + 2 + 3 * 16 + 4 * 8 + 7 * 16 + 3 * 8 + 2 * 4 + 4 * 8 + 4 * 8 + 3 * 8;

    /// The caps that must be non-zero, by name, with their values.
    fn caps(&self) -> [(&'static str, u64); 8] {
        [
            ("ComputePoolParamsV1.max_work_units", self.max_work_units),
            ("ComputePoolParamsV1.max_generations", self.max_generations),
            (
                "ComputePoolParamsV1.max_reprovisionable_units",
                self.max_reprovisionable_units,
            ),
            (
                "ComputePoolParamsV1.max_attempts_per_unit",
                u64::from(self.max_attempts_per_unit),
            ),
            (
                "ComputePoolParamsV1.max_reassignments_per_file",
                u64::from(self.max_reassignments_per_file),
            ),
            (
                "ComputePoolParamsV1.max_retention_files_per_job",
                self.max_retention_files_per_job,
            ),
            (
                "ComputePoolParamsV1.max_retention_updates_per_block",
                self.max_retention_updates_per_block,
            ),
            (
                "ComputePoolParamsV1.max_reverse_index_entries",
                self.max_reverse_index_entries,
            ),
        ]
    }

    /// `b_offer + b_commit + b_check`, checked. `None` on u128 overflow.
    pub fn bond_total(&self) -> Option<u128> {
        self.b_offer
            .checked_add(self.b_commit)?
            .checked_add(self.b_check)
    }

    /// The sum of the seven reimbursements, checked. `None` on u128 overflow.
    pub fn reimbursement_total(&self) -> Option<u128> {
        [
            self.accept_reimb,
            self.commit_verify_reimb,
            self.publish_reimb,
            self.observe_reimb,
            self.check_reimb,
            self.settle_reimb,
            self.reassign_reimb,
        ]
        .into_iter()
        .try_fold(0u128, u128::checked_add)
    }

    /// Structural validation over `&self` only. See the module docs: non-zero
    /// caps and overflow-free u128 totals; no economic assertion and no check
    /// that needs chain context.
    pub fn validate(&self) -> Result<(), DecodeError> {
        for (ctx, value) in self.caps() {
            if value == 0 {
                return Err(DecodeError::BadValue { ctx });
            }
        }
        if self.bond_total().is_none() {
            return Err(DecodeError::BadValue {
                ctx: "ComputePoolParamsV1.bond_total",
            });
        }
        if self.reimbursement_total().is_none() {
            return Err(DecodeError::BadValue {
                ctx: "ComputePoolParamsV1.reimbursement_total",
            });
        }
        Ok(())
    }

    /// The fixed-width layout of this value, without validation. For
    /// committing a value exactly as declared; the canonical route for a value
    /// that must be valid is [`try_encode`](Self::try_encode).
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(&Self::MAGIC);
        w.u16(Self::SCHEMA_VERSION);
        for v in [self.b_offer, self.b_commit, self.b_check] {
            w.bytes(&v.to_le_bytes());
        }
        for v in [self.c_layer, self.c_tok, self.c_sel, self.c_emit] {
            w.u64(v);
        }
        for v in [
            self.accept_reimb,
            self.commit_verify_reimb,
            self.publish_reimb,
            self.observe_reimb,
            self.check_reimb,
            self.settle_reimb,
            self.reassign_reimb,
        ] {
            w.bytes(&v.to_le_bytes());
        }
        for v in [
            self.max_work_units,
            self.max_generations,
            self.max_reprovisionable_units,
        ] {
            w.u64(v);
        }
        w.u32(self.max_attempts_per_unit);
        w.u32(self.max_reassignments_per_file);
        for v in [
            self.k_susp,
            self.w_susp,
            self.s_susp,
            self.n_invite_max,
            self.max_retention_files_per_job,
            self.max_retention_updates_per_block,
            self.max_reverse_index_entries,
            self.output_availability_blocks,
            self.d_avail,
            self.d_ack,
            self.d_final,
        ] {
            w.u64(v);
        }
        w.into_bytes()
    }

    /// Canonical encode: validates structurally, then emits the fixed
    /// [`LEN`](Self::LEN)-byte layout. `Err` iff [`validate`](Self::validate) fails.
    pub fn try_encode(&self) -> Result<Vec<u8>, DecodeError> {
        self.validate()?;
        Ok(self.canonical_bytes())
    }

    /// Decode from a reader: magic, schema version, every field, then
    /// structural validation. Truncation is rejected.
    pub fn decode(r: &mut Reader) -> Result<Self, DecodeError> {
        let magic = r.read_array::<7>("ComputePoolParamsV1.magic")?;
        if magic != Self::MAGIC {
            return Err(DecodeError::BadTag {
                ctx: "ComputePoolParamsV1",
            });
        }
        let sv = r.read_u16("ComputePoolParamsV1.schema_version")?;
        if sv != Self::SCHEMA_VERSION {
            return Err(DecodeError::BadFixedScalar {
                ctx: "ComputePoolParamsV1.schema_version",
                value: u64::from(sv),
            });
        }
        let u128_le = |r: &mut Reader, ctx| r.read_array::<16>(ctx).map(u128::from_le_bytes);
        let v = Self {
            b_offer: u128_le(r, "ComputePoolParamsV1.b_offer")?,
            b_commit: u128_le(r, "ComputePoolParamsV1.b_commit")?,
            b_check: u128_le(r, "ComputePoolParamsV1.b_check")?,
            c_layer: r.read_u64("ComputePoolParamsV1.c_layer")?,
            c_tok: r.read_u64("ComputePoolParamsV1.c_tok")?,
            c_sel: r.read_u64("ComputePoolParamsV1.c_sel")?,
            c_emit: r.read_u64("ComputePoolParamsV1.c_emit")?,
            accept_reimb: u128_le(r, "ComputePoolParamsV1.accept_reimb")?,
            commit_verify_reimb: u128_le(r, "ComputePoolParamsV1.commit_verify_reimb")?,
            publish_reimb: u128_le(r, "ComputePoolParamsV1.publish_reimb")?,
            observe_reimb: u128_le(r, "ComputePoolParamsV1.observe_reimb")?,
            check_reimb: u128_le(r, "ComputePoolParamsV1.check_reimb")?,
            settle_reimb: u128_le(r, "ComputePoolParamsV1.settle_reimb")?,
            reassign_reimb: u128_le(r, "ComputePoolParamsV1.reassign_reimb")?,
            max_work_units: r.read_u64("ComputePoolParamsV1.max_work_units")?,
            max_generations: r.read_u64("ComputePoolParamsV1.max_generations")?,
            max_reprovisionable_units: r
                .read_u64("ComputePoolParamsV1.max_reprovisionable_units")?,
            max_attempts_per_unit: r.read_u32("ComputePoolParamsV1.max_attempts_per_unit")?,
            max_reassignments_per_file: r
                .read_u32("ComputePoolParamsV1.max_reassignments_per_file")?,
            k_susp: r.read_u64("ComputePoolParamsV1.k_susp")?,
            w_susp: r.read_u64("ComputePoolParamsV1.w_susp")?,
            s_susp: r.read_u64("ComputePoolParamsV1.s_susp")?,
            n_invite_max: r.read_u64("ComputePoolParamsV1.n_invite_max")?,
            max_retention_files_per_job: r
                .read_u64("ComputePoolParamsV1.max_retention_files_per_job")?,
            max_retention_updates_per_block: r
                .read_u64("ComputePoolParamsV1.max_retention_updates_per_block")?,
            max_reverse_index_entries: r
                .read_u64("ComputePoolParamsV1.max_reverse_index_entries")?,
            output_availability_blocks: r
                .read_u64("ComputePoolParamsV1.output_availability_blocks")?,
            d_avail: r.read_u64("ComputePoolParamsV1.d_avail")?,
            d_ack: r.read_u64("ComputePoolParamsV1.d_ack")?,
            d_final: r.read_u64("ComputePoolParamsV1.d_final")?,
        };
        v.validate()?;
        Ok(v)
    }

    /// Decode consuming exactly `bytes` (trailing bytes rejected).
    pub fn decode_exact(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let v = Self::decode(&mut r)?;
        r.finish("ComputePoolParamsV1")?;
        Ok(v)
    }
}
