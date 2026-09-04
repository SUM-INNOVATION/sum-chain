//! C1 ComputePool-27 wire op family (#130 / #217).
//!
//! DORMANT: consensus BYTES only. ComputePool execution is gate-closed
//! (`compute_pool_enabled_from_height = None`, fail-closed in genesis validate).
//! This module defines the manual-codec op carriers a ComputePool transaction
//! will carry once activated; it wires nothing into execution.
//!
//! ## Frozen conventions reused (no invention)
//! Each op follows the `beacon_wire` template verbatim: a 7-byte `MAGIC`
//! (`"CPxxvN\0"`), a `u16 SCHEMA_VERSION`, fixed-width **little-endian** fields,
//! and `encode / try_encode / decode / decode_exact` where `decode_exact` rejects
//! trailing bytes via `Reader::finish`. Op discriminants OR the ComputePool op
//! namespace `0xC100` (#217 A2). The dispatch enum peeks the leading 7-byte magic
//! (like `BeaconOperation`). The `ComputePoolTxData` serde wrapper
//! (`crate::transaction`) carries the opaque canonical `op_bytes: Vec<u8>` inside
//! `TxPayload::ComputePool` at ordinal 27 (the reserved slot, filled in place,
//! #130). EXECUTION stays gate-closed; mempool admission rejects ComputePool txs
//! while dormant.
//!
//! ## Encoding rulings (owner, 2026-09-02)
//! * **Ids that REFERENCE an existing entity are carried** as `[u8; 32]`
//!   (`job_id`, `commit_bond_id`) — a reference must name the thing it references.
//! * **Derived / assignment-selected ids are NOT carried.** The winning
//!   `offer_bond_id` an accept refers to is DERIVED from the assignment state at
//!   execution (not carried), so an accept cannot name a different offer than the
//!   assignment selected. An offer's own `offer_bond_id` is DERIVED from the
//!   chain id, the sender, and `offer_seq` (draft §K:288) — the op carries
//!   `offer_seq`, not the id, so a submitter cannot present a forged id.
//! * **Work-item identity** = `job_id[32] ‖ unit_id[32] ‖ generation u64` (the C3
//!   routing precedent, draft §F), carried in FULL (generation included) by every
//!   op that targets a work item (accept/decline/expire) — this prevents
//!   stale-generation ambiguity.
//! * **Economic amounts are governance/state values, NOT transaction operands**
//!   (#217 B6/B7): op bodies carry only 32-byte bond *handles* and per-op operands
//!   (`offered_bytes`, `accepted_bytes`), never bond/reimbursement *amounts*.
//! * **Caller authorization is validated from the transaction sender + state**,
//!   never duplicated in the operation bytes (who may expire/decline/cancel is an
//!   execution-layer rule).
//! * **No numeric receipt codes are allocated yet.**
//!
//! ## Scope of this module
//! All **eight** C1 ops, each byte-determined by a ratified ruling:
//! `CreateComputePoolJobV1`, `PublishBondedOfferV1`, `AcceptWorkUnitV1`,
//! `DeclineWorkUnitV1`, `ExpireWorkUnitV1`, `CancelJobV1`, `AssignWorkUnitV1`,
//! `ReassignWorkUnitV1`.
//!
//! ## The eight ops at a glance (#213)
//!
//! Every carrier is FIXED-WIDTH, so `LEN` is exact — there is no length prefix
//! and no variable field anywhere in the family.
//!
//! | op | magic | type | LEN |
//! |---|---|---|---|
//! | `0xC101` | `CPJBv1\0` | [`CreateComputePoolJobV1`] | 77 |
//! | `0xC102` | `CPOFv1\0` | [`PublishBondedOfferV1`] | 53 |
//! | `0xC103` | `CPACv1\0` | [`AcceptWorkUnitV1`] | 129 |
//! | `0xC104` | `CPDCv1\0` | [`DeclineWorkUnitV1`] | 81 |
//! | `0xC105` | `CPEXv1\0` | [`ExpireWorkUnitV1`] | 81 |
//! | `0xC106` | `CPCNv1\0` | [`CancelJobV1`] | 41 |
//! | `0xC107` | `CPASv1\0` | [`AssignWorkUnitV1`] | 81 |
//! | `0xC108` | `CPRAv1\0` | [`ReassignWorkUnitV1`] | 81 |
//!
//! Per-op byte-offset tables are on each type; the ordinal-27 **routing prefix**
//! is on [`WorkItemRef`]. Frozen golden vectors for all eight (plus the prefix
//! offsets) live in `tests/compute_pool_wire_golden.rs`, which is append-only.
//! The same tables are mirrored in `docs/design/C1-COMPUTEPOOL-OPS.md`.
//!
//! **Architecture independence is structural:** every field is fixed-width and
//! explicitly little-endian and no encoder consults host layout, so the vectors
//! are identical on x86_64 and aarch64 — CI runs the suite on both.
//!
//! * `AssignWorkUnit`/`ReassignWorkUnit` carry only a `WorkItemRef`; their
//!   winner/score (binding the RATIFIED v1 `beacon_output`, #223) is
//!   consensus-computed in the dormant execution layer, not on the wire.
//! * `CreateComputePoolJobV1` (#227) **commits** its dependency graph as a single
//!   `graph_definition_root`; the graph's canonical encoding, the pool identifier
//!   KDFs and the ceiling-derived structural limits live in
//!   [`crate::compute_pool_graph`].

use crate::address::Address;
use crate::b0::codec::{DecodeError, Reader, Writer};

/// ComputePool op namespace (#217 A2): op discriminants are `0xC100 | op`.
pub const COMPUTE_POOL_OP_NAMESPACE: u16 = 0xC100;

pub const OP_CREATE_JOB: u16 = COMPUTE_POOL_OP_NAMESPACE | 0x01;
pub const OP_PUBLISH_OFFER: u16 = COMPUTE_POOL_OP_NAMESPACE | 0x02;
pub const OP_ACCEPT_UNIT: u16 = COMPUTE_POOL_OP_NAMESPACE | 0x03;
pub const OP_DECLINE_UNIT: u16 = COMPUTE_POOL_OP_NAMESPACE | 0x04;
pub const OP_EXPIRE_UNIT: u16 = COMPUTE_POOL_OP_NAMESPACE | 0x05;
pub const OP_CANCEL_JOB: u16 = COMPUTE_POOL_OP_NAMESPACE | 0x06;
pub const OP_ASSIGN_UNIT: u16 = COMPUTE_POOL_OP_NAMESPACE | 0x07;
pub const OP_REASSIGN_UNIT: u16 = COMPUTE_POOL_OP_NAMESPACE | 0x08;

/// A work-item coordinate on the wire: `job_id ‖ unit_id ‖ generation`
/// (draft §F routing order). 72 bytes.
///
/// This is the **ordinal-27 routing prefix**. It is embedded verbatim at the same
/// place in every op that targets a work item (accept / decline / expire / assign
/// / reassign), i.e. at absolute offset `+9`, immediately after that op's 9-byte
/// `MAGIC ‖ schema_version` header:
///
/// | off (in prefix) | size | field | notes |
/// |---|---|---|---|
/// | 0 | 32 | `job_id` | derived (§K); references an existing job |
/// | 32 | 32 | `unit_id` | derived (§K) from `job_id` + `unit_index` |
/// | 64 | 8 | `generation` | `u64` **LE**; carried in FULL (anti-stale) |
///
/// Carrying `generation` in full is what makes a stale-generation reference
/// unambiguous: the same `(job, unit)` at a different generation is different
/// bytes and cannot be substituted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkItemRef {
    pub job_id: [u8; 32],
    pub unit_id: [u8; 32],
    pub generation: u64,
}

impl WorkItemRef {
    pub const LEN: usize = 32 + 32 + 8;
    fn write(&self, w: &mut Writer) {
        w.bytes(&self.job_id);
        w.bytes(&self.unit_id);
        w.u64(self.generation);
    }
    fn read(r: &mut Reader, ctx: &'static str) -> Result<Self, DecodeError> {
        let job_id = r.read_array::<32>(ctx)?;
        let unit_id = r.read_array::<32>(ctx)?;
        let generation = r.read_u64(ctx)?;
        Ok(Self { job_id, unit_id, generation })
    }
}

// ===========================================================================
// 0. CreateComputePoolJobV1  (#227)
// ===========================================================================

/// Create a compute-pool job (op `0xC101`), 77 B fixed.
///
/// | off | size | field |
/// |---|---|---|
/// | 0 | 7 | `MAGIC = "CPJBv1\0"` |
/// | 7 | 2 | `schema_version` `u16` LE `= 1` |
/// | 9 | 32 | `client_job_salt` |
/// | 41 | 32 | `graph_definition_root` |
/// | 73 | 4 | `unit_count` `u32` LE |
///
/// The op **commits** its dependency graph rather than inlining it: the graph's
/// canonical encoding ([`crate::compute_pool_graph::GraphDefinitionV1`]) hashes
/// to `graph_definition_root` under the pool graph domain (ratified B5).
///
/// * `client_job_salt` — the only `job_id` input a submitter provides; execution
///   recomputes `job_id` from the chain id, the **transaction sender**, the
///   sender's nonce and this salt (§K), so the id cannot be forged.
/// * `unit_count` — a cheap early bound, cross-checked against the revealed
///   graph (`Inconsistent` on mismatch).
/// * **No economic operand.** Per the owner ruling, amounts (the base quote `q`,
///   bonds, allowances, reimbursements) are governance/state — `requester_debit`
///   is computed at execution from governance params and the job's structure.
/// * **No `sizing` list.** Per-unit `retention_slots` lives *inside* the graph so
///   the commitment binds it (it drives retention and funding).
/// * **No authorization field.** The requester is the tx sender; `job_id` binds
///   sender + nonce, so authority is implicit in the derivation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateComputePoolJobV1 {
    pub client_job_salt: [u8; 32],
    pub graph_definition_root: [u8; 32],
    pub unit_count: u32,
}

impl CreateComputePoolJobV1 {
    pub const MAGIC: [u8; 7] = *b"CPJBv1\0";
    pub const SCHEMA_VERSION: u16 = 1;
    pub const LEN: usize = 7 + 2 + 32 + 32 + 4; // 77

    pub fn validate(&self) -> Result<(), DecodeError> {
        // The declared unit_count can never exceed what the graph ceiling allows.
        if self.unit_count > crate::compute_pool_graph::GraphDefinitionV1::MAX_UNITS {
            return Err(DecodeError::CountExceedsMax {
                ctx: "CreateComputePoolJobV1.unit_count",
                count: self.unit_count as u64,
                max: crate::compute_pool_graph::GraphDefinitionV1::MAX_UNITS as u64,
            });
        }
        Ok(())
    }

    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(&Self::MAGIC);
        w.u16(Self::SCHEMA_VERSION);
        w.bytes(&self.client_job_salt);
        w.bytes(&self.graph_definition_root);
        w.u32(self.unit_count);
        w.into_bytes()
    }

    pub fn try_encode(&self) -> Result<Vec<u8>, DecodeError> {
        self.validate()?;
        Ok(self.encode())
    }

    pub fn decode(r: &mut Reader) -> Result<Self, DecodeError> {
        check_magic(r, &Self::MAGIC, "CreateComputePoolJobV1")?;
        check_schema(r, Self::SCHEMA_VERSION, "CreateComputePoolJobV1.schema_version")?;
        let client_job_salt = r.read_array::<32>("CreateComputePoolJobV1.client_job_salt")?;
        let graph_definition_root =
            r.read_array::<32>("CreateComputePoolJobV1.graph_definition_root")?;
        let unit_count = r.read_u32("CreateComputePoolJobV1.unit_count")?;
        let v = Self {
            client_job_salt,
            graph_definition_root,
            unit_count,
        };
        v.validate()?;
        Ok(v)
    }

    pub fn decode_exact(bytes: &[u8]) -> Result<Self, DecodeError> {
        decode_exact(bytes, Self::decode, "CreateComputePoolJobV1")
    }

    /// Bind a revealed graph to this commitment: the root must match and the
    /// declared `unit_count` must equal the graph's.
    pub fn verify_graph(
        &self,
        graph: &crate::compute_pool_graph::GraphDefinitionV1,
    ) -> Result<(), DecodeError> {
        if graph.units.len() as u64 != self.unit_count as u64 {
            return Err(DecodeError::Inconsistent {
                ctx: "CreateComputePoolJobV1.unit_count vs GraphDefinitionV1",
            });
        }
        if graph.root()? != self.graph_definition_root {
            return Err(DecodeError::Inconsistent {
                ctx: "CreateComputePoolJobV1.graph_definition_root",
            });
        }
        Ok(())
    }
}

// ===========================================================================
// 1. PublishBondedOfferV1
// ===========================================================================

/// Publish a bonded capacity offer (op `0xC102`), 53 B fixed.
///
/// | off | size | field |
/// |---|---|---|
/// | 0 | 7 | `MAGIC = "CPOFv1\0"` |
/// | 7 | 2 | `schema_version` `u16` LE `= 1` |
/// | 9 | 8 | `offer_seq` `u64` LE |
/// | 17 | 16 | `offered_bytes` `u128` LE |
/// | 33 | 20 | `payment_addr` |
///
/// `offer_bond_id` is DERIVED at execution from
/// the chain id, the sender, and `offer_seq` (draft §K:288), so it is not carried
/// (a submitter cannot present a forged id). `identity` (= the sender),
/// `bond_locked` (`B_offer`, a governance value), and the internal `active` flag
/// are NOT encoded (owner ruling 2026-09-02).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishBondedOfferV1 {
    pub offer_seq: u64,
    pub offered_bytes: u128,
    pub payment_addr: Address,
}

impl PublishBondedOfferV1 {
    pub const MAGIC: [u8; 7] = *b"CPOFv1\0";
    pub const SCHEMA_VERSION: u16 = 1;
    pub const LEN: usize = 7 + 2 + 8 + 16 + 20; // 53

    pub fn validate(&self) -> Result<(), DecodeError> {
        Ok(())
    }

    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(&Self::MAGIC);
        w.u16(Self::SCHEMA_VERSION);
        w.u64(self.offer_seq);
        w.bytes(&self.offered_bytes.to_le_bytes());
        w.bytes(self.payment_addr.as_bytes());
        w.into_bytes()
    }

    pub fn try_encode(&self) -> Result<Vec<u8>, DecodeError> {
        self.validate()?;
        Ok(self.encode())
    }

    pub fn decode(r: &mut Reader) -> Result<Self, DecodeError> {
        check_magic(r, &Self::MAGIC, "PublishBondedOfferV1")?;
        check_schema(r, Self::SCHEMA_VERSION, "PublishBondedOfferV1.schema_version")?;
        let offer_seq = r.read_u64("PublishBondedOfferV1.offer_seq")?;
        let offered_bytes = read_u128(r, "PublishBondedOfferV1.offered_bytes")?;
        let payment_addr = Address::new(r.read_array::<20>("PublishBondedOfferV1.payment_addr")?);
        Ok(Self { offer_seq, offered_bytes, payment_addr })
    }

    pub fn decode_exact(bytes: &[u8]) -> Result<Self, DecodeError> {
        decode_exact(bytes, Self::decode, "PublishBondedOfferV1")
    }
}

// ===========================================================================
// 2. AcceptWorkUnitV1
// ===========================================================================

/// Accept an assigned work unit (op `0xC103`), 129 B fixed.
///
/// | off | size | field |
/// |---|---|---|
/// | 0 | 7 | `MAGIC = "CPACv1\0"` |
/// | 7 | 2 | `schema_version` `u16` LE `= 1` |
/// | 9 | 72 | [`WorkItemRef`] — the routing prefix (`job_id ‖ unit_id ‖ generation`) |
/// | 81 | 32 | `commit_bond_id` |
/// | 113 | 16 | `accepted_bytes` `u128` LE |
///
/// References the assigned work item (full
/// `WorkItemRef`, generation included) and takes a commit-bond handle
/// (`commit_bond_id`; the `B_commit` amount is a governance value, not carried).
/// The winning `offer_bond_id` is NOT carried — it is DERIVED from the assignment
/// state at execution (owner ruling 2026-09-02), so the accept cannot name a
/// different offer than the one the assignment selected. Actor = the assigned
/// worker (tx sender).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptWorkUnitV1 {
    pub work_item: WorkItemRef,
    pub commit_bond_id: [u8; 32],
    pub accepted_bytes: u128,
}

impl AcceptWorkUnitV1 {
    pub const MAGIC: [u8; 7] = *b"CPACv1\0";
    pub const SCHEMA_VERSION: u16 = 1;
    pub const LEN: usize = 7 + 2 + WorkItemRef::LEN + 32 + 16; // 129

    pub fn validate(&self) -> Result<(), DecodeError> {
        Ok(())
    }

    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(&Self::MAGIC);
        w.u16(Self::SCHEMA_VERSION);
        self.work_item.write(&mut w);
        w.bytes(&self.commit_bond_id);
        w.bytes(&self.accepted_bytes.to_le_bytes());
        w.into_bytes()
    }

    pub fn try_encode(&self) -> Result<Vec<u8>, DecodeError> {
        self.validate()?;
        Ok(self.encode())
    }

    pub fn decode(r: &mut Reader) -> Result<Self, DecodeError> {
        check_magic(r, &Self::MAGIC, "AcceptWorkUnitV1")?;
        check_schema(r, Self::SCHEMA_VERSION, "AcceptWorkUnitV1.schema_version")?;
        let work_item = WorkItemRef::read(r, "AcceptWorkUnitV1.work_item")?;
        let commit_bond_id = r.read_array::<32>("AcceptWorkUnitV1.commit_bond_id")?;
        let accepted_bytes = read_u128(r, "AcceptWorkUnitV1.accepted_bytes")?;
        Ok(Self { work_item, commit_bond_id, accepted_bytes })
    }

    pub fn decode_exact(bytes: &[u8]) -> Result<Self, DecodeError> {
        decode_exact(bytes, Self::decode, "AcceptWorkUnitV1")
    }
}

// ===========================================================================
// 3/4. Decline / Expire — both target a work item and carry only its reference.
// (Distinct magics/ops; the authorization difference — worker-declines vs the
// permissionless timeout-expiry — is an execution-layer rule, not a wire field.)
// ===========================================================================

// Defines a work-item-only op carrier: decline `0xC104`, expire `0xC105`,
// assign `0xC107`, reassign `0xC108`. Each generated type carries its own
// byte-offset table (emitted below); `ops_do_not_cross_decode` in the golden
// suite proves the shared layout cannot be confused across ops.
macro_rules! work_item_op {
    ($name:ident, $magic:literal, $ctx:literal) => {
        #[doc = concat!("`", $ctx, "` — work-item op, 81 B fixed.")]
        #[doc = ""]
        #[doc = "| off | size | field |"]
        #[doc = "|---|---|---|"]
        #[doc = concat!("| 0 | 7 | `MAGIC = ", stringify!($magic), "` |")]
        #[doc = "| 7 | 2 | `schema_version` `u16` LE `= 1` |"]
        #[doc = "| 9 | 72 | [`WorkItemRef`] — the routing prefix (`job_id ‖ unit_id ‖ generation`) |"]
        #[doc = ""]
        #[doc = "The four work-item ops share this layout, differing only in `MAGIC`"]
        #[doc = "and op id. That is safe because the magics are pairwise distinct and"]
        #[doc = "each decoder checks its own, so one op's bytes are rejected by a"]
        #[doc = "sibling decoder and can never be reinterpreted as another op."]
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct $name {
            pub work_item: WorkItemRef,
        }
        impl $name {
            pub const MAGIC: [u8; 7] = *$magic;
            pub const SCHEMA_VERSION: u16 = 1;
            pub const LEN: usize = 7 + 2 + WorkItemRef::LEN; // 81

            pub fn validate(&self) -> Result<(), DecodeError> {
                Ok(())
            }
            fn encode(&self) -> Vec<u8> {
                let mut w = Writer::new();
                w.bytes(&Self::MAGIC);
                w.u16(Self::SCHEMA_VERSION);
                self.work_item.write(&mut w);
                w.into_bytes()
            }
            pub fn try_encode(&self) -> Result<Vec<u8>, DecodeError> {
                self.validate()?;
                Ok(self.encode())
            }
            pub fn decode(r: &mut Reader) -> Result<Self, DecodeError> {
                check_magic(r, &Self::MAGIC, $ctx)?;
                check_schema(r, Self::SCHEMA_VERSION, concat!($ctx, ".schema_version"))?;
                let work_item = WorkItemRef::read(r, concat!($ctx, ".work_item"))?;
                Ok(Self { work_item })
            }
            pub fn decode_exact(bytes: &[u8]) -> Result<Self, DecodeError> {
                decode_exact(bytes, Self::decode, $ctx)
            }
        }
    };
}

work_item_op!(DeclineWorkUnitV1, b"CPDCv1\0", "DeclineWorkUnitV1");
work_item_op!(ExpireWorkUnitV1, b"CPEXv1\0", "ExpireWorkUnitV1");

// ===========================================================================
// 6/7. Assign / Reassign — target a work item (full WorkItemRef).
//
// The wire body is ONLY the work-item reference. The winner (offer_bond_id,
// payment_addr, score) is CONSENSUS-COMPUTED at execution from pool state and the
// BR1 beacon output — NOT submitter-provided — so it is not carried. Both ops
// drive a `-> Assigned` transition via the deterministic winner selection, whose
// score binds the (RATIFIED v1, #223) `beacon_output`:
//   score preimage = "OMNINODE-POOL-ASSIGN:v1:" ‖ beacon ‖ job_id ‖ unit_id ‖
//                    generation(u64) ‖ payment_addr ‖ offer_bond_id
// That selection lives in the (dormant) execution layer; this module fixes only
// the op-carrier bytes. Same `WorkItemRef` shape as decline/expire (distinct
// magics/op ids); generation is carried in full (anti-stale).
// ===========================================================================
work_item_op!(AssignWorkUnitV1, b"CPASv1\0", "AssignWorkUnitV1");
work_item_op!(ReassignWorkUnitV1, b"CPRAv1\0", "ReassignWorkUnitV1");

// ===========================================================================
// 5. CancelJobV1
// ===========================================================================

/// Cancel a job (op `0xC106`), 41 B fixed.
///
/// | off | size | field |
/// |---|---|---|
/// | 0 | 7 | `MAGIC = "CPCNv1\0"` |
/// | 7 | 2 | `schema_version` `u16` LE `= 1` |
/// | 9 | 32 | `job_id` |
///
/// References the job by id. Actor = the job requester (tx sender);
/// refunds/burns are settlement concerns applied at execution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CancelJobV1 {
    pub job_id: [u8; 32],
}

impl CancelJobV1 {
    pub const MAGIC: [u8; 7] = *b"CPCNv1\0";
    pub const SCHEMA_VERSION: u16 = 1;
    pub const LEN: usize = 7 + 2 + 32; // 41

    pub fn validate(&self) -> Result<(), DecodeError> {
        Ok(())
    }

    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(&Self::MAGIC);
        w.u16(Self::SCHEMA_VERSION);
        w.bytes(&self.job_id);
        w.into_bytes()
    }

    pub fn try_encode(&self) -> Result<Vec<u8>, DecodeError> {
        self.validate()?;
        Ok(self.encode())
    }

    pub fn decode(r: &mut Reader) -> Result<Self, DecodeError> {
        check_magic(r, &Self::MAGIC, "CancelJobV1")?;
        check_schema(r, Self::SCHEMA_VERSION, "CancelJobV1.schema_version")?;
        let job_id = r.read_array::<32>("CancelJobV1.job_id")?;
        Ok(Self { job_id })
    }

    pub fn decode_exact(bytes: &[u8]) -> Result<Self, DecodeError> {
        decode_exact(bytes, Self::decode, "CancelJobV1")
    }
}

// ===========================================================================
// Dispatch
// ===========================================================================

/// A decoded ComputePool operation. The wire form is the inner carrier's bytes;
/// the discriminant is recovered by peeking the leading 7-byte magic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ComputePoolOperation {
    CreateJob(CreateComputePoolJobV1),
    PublishOffer(PublishBondedOfferV1),
    AcceptUnit(AcceptWorkUnitV1),
    DeclineUnit(DeclineWorkUnitV1),
    ExpireUnit(ExpireWorkUnitV1),
    CancelJob(CancelJobV1),
    AssignUnit(AssignWorkUnitV1),
    ReassignUnit(ReassignWorkUnitV1),
}

impl ComputePoolOperation {
    pub fn op(&self) -> u16 {
        match self {
            ComputePoolOperation::CreateJob(_) => OP_CREATE_JOB,
            ComputePoolOperation::PublishOffer(_) => OP_PUBLISH_OFFER,
            ComputePoolOperation::AcceptUnit(_) => OP_ACCEPT_UNIT,
            ComputePoolOperation::DeclineUnit(_) => OP_DECLINE_UNIT,
            ComputePoolOperation::ExpireUnit(_) => OP_EXPIRE_UNIT,
            ComputePoolOperation::CancelJob(_) => OP_CANCEL_JOB,
            ComputePoolOperation::AssignUnit(_) => OP_ASSIGN_UNIT,
            ComputePoolOperation::ReassignUnit(_) => OP_REASSIGN_UNIT,
        }
    }

    pub fn try_encode(&self) -> Result<Vec<u8>, DecodeError> {
        match self {
            ComputePoolOperation::CreateJob(v) => v.try_encode(),
            ComputePoolOperation::PublishOffer(v) => v.try_encode(),
            ComputePoolOperation::AcceptUnit(v) => v.try_encode(),
            ComputePoolOperation::DeclineUnit(v) => v.try_encode(),
            ComputePoolOperation::ExpireUnit(v) => v.try_encode(),
            ComputePoolOperation::CancelJob(v) => v.try_encode(),
            ComputePoolOperation::AssignUnit(v) => v.try_encode(),
            ComputePoolOperation::ReassignUnit(v) => v.try_encode(),
        }
    }

    pub fn decode_exact(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let magic = r.peek_array::<7>("ComputePoolOperation.magic")?;
        let op = match &magic {
            m if *m == CreateComputePoolJobV1::MAGIC => {
                ComputePoolOperation::CreateJob(CreateComputePoolJobV1::decode(&mut r)?)
            }
            m if *m == PublishBondedOfferV1::MAGIC => {
                ComputePoolOperation::PublishOffer(PublishBondedOfferV1::decode(&mut r)?)
            }
            m if *m == AcceptWorkUnitV1::MAGIC => {
                ComputePoolOperation::AcceptUnit(AcceptWorkUnitV1::decode(&mut r)?)
            }
            m if *m == DeclineWorkUnitV1::MAGIC => {
                ComputePoolOperation::DeclineUnit(DeclineWorkUnitV1::decode(&mut r)?)
            }
            m if *m == ExpireWorkUnitV1::MAGIC => {
                ComputePoolOperation::ExpireUnit(ExpireWorkUnitV1::decode(&mut r)?)
            }
            m if *m == CancelJobV1::MAGIC => {
                ComputePoolOperation::CancelJob(CancelJobV1::decode(&mut r)?)
            }
            m if *m == AssignWorkUnitV1::MAGIC => {
                ComputePoolOperation::AssignUnit(AssignWorkUnitV1::decode(&mut r)?)
            }
            m if *m == ReassignWorkUnitV1::MAGIC => {
                ComputePoolOperation::ReassignUnit(ReassignWorkUnitV1::decode(&mut r)?)
            }
            _ => return Err(DecodeError::BadTag { ctx: "ComputePoolOperation" }),
        };
        r.finish("ComputePoolOperation")?;
        Ok(op)
    }
}

// ===========================================================================
// Shared codec helpers
// ===========================================================================

fn check_magic(r: &mut Reader, expected: &[u8; 7], ctx: &'static str) -> Result<(), DecodeError> {
    let magic = r.read_array::<7>(ctx)?;
    if magic != *expected {
        return Err(DecodeError::BadTag { ctx });
    }
    Ok(())
}

fn check_schema(r: &mut Reader, expected: u16, ctx: &'static str) -> Result<(), DecodeError> {
    let sv = r.read_u16(ctx)?;
    if sv != expected {
        return Err(DecodeError::BadFixedScalar { ctx, value: sv as u64 });
    }
    Ok(())
}

fn read_u128(r: &mut Reader, ctx: &'static str) -> Result<u128, DecodeError> {
    Ok(u128::from_le_bytes(r.read_array::<16>(ctx)?))
}

fn decode_exact<T>(
    bytes: &[u8],
    decode: impl Fn(&mut Reader) -> Result<T, DecodeError>,
    ctx: &'static str,
) -> Result<T, DecodeError> {
    let mut r = Reader::new(bytes);
    let v = decode(&mut r)?;
    r.finish(ctx)?;
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(b: u8) -> Address {
        Address::new([b; 20])
    }
    fn wi() -> WorkItemRef {
        WorkItemRef { job_id: [0x11; 32], unit_id: [0x22; 32], generation: 5 }
    }

    fn create_job() -> CreateComputePoolJobV1 {
        CreateComputePoolJobV1 {
            client_job_salt: [0xAA; 32],
            graph_definition_root: [0xBB; 32],
            unit_count: 3,
        }
    }
    fn publish_offer() -> PublishBondedOfferV1 {
        PublishBondedOfferV1 { offer_seq: 9, offered_bytes: 1 << 40, payment_addr: addr(0x07) }
    }
    fn accept() -> AcceptWorkUnitV1 {
        AcceptWorkUnitV1 { work_item: wi(), commit_bond_id: [0x44; 32], accepted_bytes: 4096 }
    }

    #[test]
    fn op_namespace_discriminants() {
        assert_eq!(OP_PUBLISH_OFFER, 0xC102);
        assert_eq!(OP_ACCEPT_UNIT, 0xC103);
        assert_eq!(OP_CANCEL_JOB, 0xC106);
        assert_eq!(OP_ASSIGN_UNIT, 0xC107);
        assert_eq!(OP_REASSIGN_UNIT, 0xC108);
        assert_eq!(OP_CREATE_JOB, 0xC101);
    }

    #[test]
    fn fixed_lengths() {
        assert_eq!(publish_offer().try_encode().unwrap().len(), PublishBondedOfferV1::LEN);
        assert_eq!(PublishBondedOfferV1::LEN, 53);
        assert_eq!(accept().try_encode().unwrap().len(), AcceptWorkUnitV1::LEN);
        assert_eq!(AcceptWorkUnitV1::LEN, 129);
        assert_eq!(
            DeclineWorkUnitV1 { work_item: wi() }.try_encode().unwrap().len(),
            DeclineWorkUnitV1::LEN
        );
        assert_eq!(CancelJobV1 { job_id: [1; 32] }.try_encode().unwrap().len(), CancelJobV1::LEN);
    }

    #[test]
    fn roundtrip_all_ops() {
        let ops = [
            ComputePoolOperation::CreateJob(create_job()),
            ComputePoolOperation::PublishOffer(publish_offer()),
            ComputePoolOperation::AcceptUnit(accept()),
            ComputePoolOperation::DeclineUnit(DeclineWorkUnitV1 { work_item: wi() }),
            ComputePoolOperation::ExpireUnit(ExpireWorkUnitV1 { work_item: wi() }),
            ComputePoolOperation::CancelJob(CancelJobV1 { job_id: [0x55; 32] }),
            ComputePoolOperation::AssignUnit(AssignWorkUnitV1 { work_item: wi() }),
            ComputePoolOperation::ReassignUnit(ReassignWorkUnitV1 { work_item: wi() }),
        ];
        for op in ops {
            let bytes = op.try_encode().unwrap();
            assert_eq!(ComputePoolOperation::decode_exact(&bytes).unwrap(), op);
        }
        // All eight ops have distinct op ids.
        let ids: std::collections::BTreeSet<u16> = [
            OP_CREATE_JOB, OP_PUBLISH_OFFER, OP_ACCEPT_UNIT, OP_DECLINE_UNIT,
            OP_EXPIRE_UNIT, OP_CANCEL_JOB, OP_ASSIGN_UNIT, OP_REASSIGN_UNIT,
        ].into_iter().collect();
        assert_eq!(ids.len(), 8, "op ids must be distinct");
    }

    #[test]
    fn rejects_bad_magic() {
        let mut b = accept().try_encode().unwrap();
        b[0] ^= 0xFF;
        assert!(matches!(AcceptWorkUnitV1::decode_exact(&b), Err(DecodeError::BadTag { .. })));
        assert!(matches!(ComputePoolOperation::decode_exact(&b), Err(DecodeError::BadTag { .. })));
    }

    #[test]
    fn rejects_bad_schema() {
        let mut b = CancelJobV1 { job_id: [1; 32] }.try_encode().unwrap();
        b[7] = 0x02;
        b[8] = 0x00;
        assert!(matches!(
            CancelJobV1::decode_exact(&b),
            Err(DecodeError::BadFixedScalar { .. })
        ));
    }

    #[test]
    fn rejects_trailing_and_truncation() {
        let b = publish_offer().try_encode().unwrap();
        let mut extra = b.clone();
        extra.push(0);
        assert!(matches!(
            PublishBondedOfferV1::decode_exact(&extra),
            Err(DecodeError::TrailingBytes { .. })
        ));
        assert!(matches!(
            PublishBondedOfferV1::decode_exact(&b[..b.len() - 1]),
            Err(DecodeError::Truncated { .. })
        ));
    }

    #[test]
    fn distinct_magics_do_not_cross_decode() {
        // Each op's bytes must be rejected by a sibling decoder (distinct magics).
        let cancel = CancelJobV1 { job_id: [1; 32] }.try_encode().unwrap();
        assert!(DeclineWorkUnitV1::decode_exact(&cancel).is_err());
        let decline = DeclineWorkUnitV1 { work_item: wi() }.try_encode().unwrap();
        assert!(ExpireWorkUnitV1::decode_exact(&decline).is_err());
    }

    #[test]
    fn stale_generation_is_not_ambiguous() {
        // A work-item op binds the FULL generation; the same (job,unit) at a
        // different generation encodes to different bytes and decodes to a
        // distinct value — a stale generation cannot be substituted.
        let g5 = DeclineWorkUnitV1 { work_item: wi() };
        let mut wi6 = wi();
        wi6.generation = 6;
        let g6 = DeclineWorkUnitV1 { work_item: wi6 };
        let b5 = g5.try_encode().unwrap();
        let b6 = g6.try_encode().unwrap();
        assert_ne!(b5, b6, "different generation must produce different bytes");
        assert_eq!(DeclineWorkUnitV1::decode_exact(&b5).unwrap().work_item.generation, 5);
        assert_eq!(DeclineWorkUnitV1::decode_exact(&b6).unwrap().work_item.generation, 6);
        // Same for accept (carries the full WorkItemRef too).
        let mut a6 = accept();
        a6.work_item.generation = 6;
        assert_ne!(accept().try_encode().unwrap(), a6.try_encode().unwrap());
    }

    #[test]
    fn golden_vectors() {
        assert_eq!(
            hex::encode(CancelJobV1 { job_id: [0x55; 32] }.try_encode().unwrap()),
            "4350434e76310001005555555555555555555555555555555555555555555555555555555555555555",
        );
        assert_eq!(hex::encode(publish_offer().try_encode().unwrap()), "43504f4676310001000900000000000000000000000001000000000000000000000707070707070707070707070707070707070707");
    }
}
