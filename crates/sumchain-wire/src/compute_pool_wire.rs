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
//! (like `BeaconOperation`), and [`ComputePoolTxData`] is the serde wrapper
//! carrying the opaque canonical `op_bytes: Vec<u8>` inside `TxPayload`
//! (replace-in-place at the reserved ordinal 27).
//!
//! ## Minimal-derivation choices (the model + C-series draft are wire-independent
//! and `[ORD-LATER]`; these are documented so review can adjust them):
//! * **Ids that REFERENCE an existing entity are carried** as `[u8; 32]`
//!   (`job_id`, `unit_id`, `offer_bond_id`, `commit_bond_id`) — a reference must
//!   name the thing it references.
//! * **Ids DERIVED at creation are NOT carried; the op carries the KDF inputs**
//!   and execution recomputes the id (per the draft §K KDFs, #217 A3), so a
//!   submitter cannot present a forged id. `PublishBondedOffer` carries
//!   `offer_seq`; `CreateComputePoolJob` carries `client_job_salt`.
//! * **Work-item identity** = `job_id[32] ‖ unit_id[32] ‖ generation u64`
//!   (the C3 routing precedent, draft §F), used uniformly by every op that
//!   targets a work item (accept/decline/expire) — one identity, not two.
//! * **The dependency graph is committed as an opaque `graph_definition_root[32]`**
//!   (#217 B5, ratified: a domain-separated hash, no `ObjectKind`). The graph's
//!   *canonical internal encoding* is frozen separately before it is produced;
//!   the job op only carries the 32-byte commitment.
//! * **Economic VALUES are governance-deferred** (#217 B6/B7): op bodies carry
//!   only 32-byte bond *handles* and per-op operands (`offered_bytes`, `q`,
//!   `accepted_bytes`, retention `sizing`), never bond/reimbursement *amounts*.
//! * **The actor is the transaction sender** (implicit); no op body re-encodes
//!   the signer. Authorization (who may expire/decline/cancel) is an
//!   execution-layer rule enforced when the gate opens, not a wire field.
//!
//! ## Scope of this module
//! The six **beacon-free** ops are implemented here: `CreateComputePoolJobV1`,
//! `PublishBondedOfferV1`, `AcceptWorkUnitV1`, `DeclineWorkUnitV1`,
//! `ExpireWorkUnitV1`, `CancelJobV1`. `AssignWorkUnit` and the winner-selection
//! side of `ReassignWorkUnit` both consume the beacon output / assignment score
//! and are deferred until the beacon-output vector is locked (#223); they will be
//! added against that frozen vector.

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
// Reserved (beacon-dependent, deferred to #223): assign = 0xC107, reassign = 0xC108.
pub const OP_ASSIGN_UNIT_RESERVED: u16 = COMPUTE_POOL_OP_NAMESPACE | 0x07;
pub const OP_REASSIGN_UNIT_RESERVED: u16 = COMPUTE_POOL_OP_NAMESPACE | 0x08;

/// A work-item coordinate on the wire: `job_id ‖ unit_id ‖ generation`
/// (draft §F routing order). 72 bytes.
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
// 1. CreateComputePoolJobV1
// ===========================================================================

/// Create a compute-pool job. `job_id` is DERIVED at execution from
/// `client_job_salt` (draft §K:286: `BLAKE3(prefix ‖ chain_id ‖ requester ‖
/// requester_nonce ‖ client_job_salt)`), so it is not carried. The dependency
/// graph is committed as the opaque `graph_definition_root` (#217 B5). `q` is the
/// requester's base quote (a per-job operand); `sizing` is the per-unit retention
/// slot counts. Retention caps / max-generations / replication are governance
/// params applied at execution, not carried here (#217 B6/B7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateComputePoolJobV1 {
    pub client_job_salt: [u8; 32],
    pub graph_definition_root: [u8; 32],
    pub q: u128,
    pub sizing: Vec<u64>,
}

impl CreateComputePoolJobV1 {
    pub const MAGIC: [u8; 7] = *b"CPJBv1\0";
    pub const SCHEMA_VERSION: u16 = 1;
    /// Defensive bound on the sizing vector (per-unit slot counts).
    pub const MAX_SIZING: u32 = 1 << 20;

    pub fn validate(&self) -> Result<(), DecodeError> {
        if self.sizing.len() as u64 > Self::MAX_SIZING as u64 {
            return Err(DecodeError::CountExceedsMax {
                ctx: "CreateComputePoolJobV1.sizing",
                count: self.sizing.len() as u64,
                max: Self::MAX_SIZING as u64,
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
        w.bytes(&self.q.to_le_bytes());
        w.u32(self.sizing.len() as u32);
        for s in &self.sizing {
            w.u64(*s);
        }
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
        let graph_definition_root = r.read_array::<32>("CreateComputePoolJobV1.graph_definition_root")?;
        let q = read_u128(r, "CreateComputePoolJobV1.q")?;
        let n = r.read_u32("CreateComputePoolJobV1.sizing_len")?;
        if n > Self::MAX_SIZING {
            return Err(DecodeError::CountExceedsMax {
                ctx: "CreateComputePoolJobV1.sizing",
                count: n as u64,
                max: Self::MAX_SIZING as u64,
            });
        }
        let mut sizing = Vec::with_capacity(n as usize);
        for _ in 0..n {
            sizing.push(r.read_u64("CreateComputePoolJobV1.sizing[]")?);
        }
        let v = Self { client_job_salt, graph_definition_root, q, sizing };
        v.validate()?;
        Ok(v)
    }

    pub fn decode_exact(bytes: &[u8]) -> Result<Self, DecodeError> {
        decode_exact(bytes, Self::decode, "CreateComputePoolJobV1")
    }
}

// ===========================================================================
// 2. PublishBondedOfferV1
// ===========================================================================

/// Publish a bonded capacity offer. `offer_bond_id` is DERIVED at execution from
/// `offer_seq` + the sender (draft §K:288), so it is not carried. `bond_locked`
/// (`B_offer`) is a governance value applied at execution, not carried.
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
// 3. AcceptWorkUnitV1
// ===========================================================================

/// Accept an assigned work unit. References the assigned work item and the
/// winning offer, and takes a commit-bond handle (`commit_bond_id`; the
/// `B_commit` amount is governance). Actor = the assigned worker (tx sender).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptWorkUnitV1 {
    pub work_item: WorkItemRef,
    pub offer_bond_id: [u8; 32],
    pub commit_bond_id: [u8; 32],
    pub accepted_bytes: u128,
}

impl AcceptWorkUnitV1 {
    pub const MAGIC: [u8; 7] = *b"CPACv1\0";
    pub const SCHEMA_VERSION: u16 = 1;
    pub const LEN: usize = 7 + 2 + WorkItemRef::LEN + 32 + 32 + 16; // 161

    pub fn validate(&self) -> Result<(), DecodeError> {
        Ok(())
    }

    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(&Self::MAGIC);
        w.u16(Self::SCHEMA_VERSION);
        self.work_item.write(&mut w);
        w.bytes(&self.offer_bond_id);
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
        let offer_bond_id = r.read_array::<32>("AcceptWorkUnitV1.offer_bond_id")?;
        let commit_bond_id = r.read_array::<32>("AcceptWorkUnitV1.commit_bond_id")?;
        let accepted_bytes = read_u128(r, "AcceptWorkUnitV1.accepted_bytes")?;
        Ok(Self { work_item, offer_bond_id, commit_bond_id, accepted_bytes })
    }

    pub fn decode_exact(bytes: &[u8]) -> Result<Self, DecodeError> {
        decode_exact(bytes, Self::decode, "AcceptWorkUnitV1")
    }
}

// ===========================================================================
// 4/5. Decline / Expire — both target a work item and carry only its reference.
// (Distinct magics/ops; the authorization difference — worker-declines vs the
// permissionless timeout-expiry — is an execution-layer rule, not a wire field.)
// ===========================================================================

macro_rules! work_item_op {
    ($name:ident, $magic:literal, $ctx:literal) => {
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
// 6. CancelJobV1
// ===========================================================================

/// Cancel a job (references it by id). Actor = the job requester (tx sender);
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
            client_job_salt: [0xA1; 32],
            graph_definition_root: [0xB2; 32],
            q: 1_000_000,
            sizing: vec![1, 2, 3],
        }
    }
    fn publish_offer() -> PublishBondedOfferV1 {
        PublishBondedOfferV1 { offer_seq: 9, offered_bytes: 1 << 40, payment_addr: addr(0x07) }
    }
    fn accept() -> AcceptWorkUnitV1 {
        AcceptWorkUnitV1 {
            work_item: wi(),
            offer_bond_id: [0x33; 32],
            commit_bond_id: [0x44; 32],
            accepted_bytes: 4096,
        }
    }

    #[test]
    fn op_namespace_discriminants() {
        assert_eq!(OP_CREATE_JOB, 0xC101);
        assert_eq!(OP_CANCEL_JOB, 0xC106);
        // Beacon-dependent ops reserved, not implemented here.
        assert_eq!(OP_ASSIGN_UNIT_RESERVED, 0xC107);
        assert_eq!(OP_REASSIGN_UNIT_RESERVED, 0xC108);
    }

    #[test]
    fn fixed_lengths() {
        assert_eq!(publish_offer().try_encode().unwrap().len(), PublishBondedOfferV1::LEN);
        assert_eq!(accept().try_encode().unwrap().len(), AcceptWorkUnitV1::LEN);
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
        ];
        for op in ops {
            let bytes = op.try_encode().unwrap();
            assert_eq!(ComputePoolOperation::decode_exact(&bytes).unwrap(), op);
        }
    }

    #[test]
    fn create_job_variable_sizing_roundtrips() {
        for n in [0usize, 1, 7, 100] {
            let mut j = create_job();
            j.sizing = (0..n as u64).collect();
            let bytes = j.try_encode().unwrap();
            assert_eq!(CreateComputePoolJobV1::decode_exact(&bytes).unwrap(), j);
        }
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
    fn create_job_rejects_oversized_sizing_len() {
        // A declared sizing_len beyond MAX with no backing data must fail (count
        // guard fires before allocation/parse).
        let mut w = Writer::new();
        w.bytes(&CreateComputePoolJobV1::MAGIC);
        w.u16(CreateComputePoolJobV1::SCHEMA_VERSION);
        w.bytes(&[0u8; 32]);
        w.bytes(&[0u8; 32]);
        w.bytes(&0u128.to_le_bytes());
        w.u32(CreateComputePoolJobV1::MAX_SIZING + 1);
        assert!(matches!(
            CreateComputePoolJobV1::decode_exact(&w.into_bytes()),
            Err(DecodeError::CountExceedsMax { .. })
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
    fn golden_vectors() {
        assert_eq!(
            hex::encode(CancelJobV1 { job_id: [0x55; 32] }.try_encode().unwrap()),
            "4350434e76310001005555555555555555555555555555555555555555555555555555555555555555",
        );
        assert_eq!(hex::encode(publish_offer().try_encode().unwrap()), "43504f4676310001000900000000000000000000000001000000000000000000000707070707070707070707070707070707070707");
    }
}
