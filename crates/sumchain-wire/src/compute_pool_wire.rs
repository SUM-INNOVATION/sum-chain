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
//! (like `BeaconOperation`). When all ops land, a `ComputePoolTxData` serde
//! wrapper will carry the opaque canonical `op_bytes: Vec<u8>` inside `TxPayload`
//! (replace-in-place at the reserved ordinal 27); that integration is deferred so
//! it happens once, after every op carrier exists (see the deferred list below).
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
//! Only wire operations whose **complete bytes are determined** by the ratified
//! rulings are landed here (owner ruling, 2026-09-02): `PublishBondedOfferV1`,
//! `AcceptWorkUnitV1`, `DeclineWorkUnitV1`, `ExpireWorkUnitV1`, `CancelJobV1`.
//!
//! DEFERRED (not landed — would freeze invented bytes):
//! * `CreateComputePoolJobV1` — genuinely **blocked**: the graph representation,
//!   the dependency-edge encoding, and the derived-id rules are NOT byte-complete
//!   in the current model/draft. Tracked as a linked blocker; it will be
//!   implemented once its graph format is byte-complete. NOT guessed here.
//! * `AssignWorkUnit` and `ReassignWorkUnit` — both consume the beacon output /
//!   assignment score (the winner-selection edge). Implemented together against
//!   the locked `beacon_output` KAT once #223/#225 merges.

use crate::address::Address;
use crate::b0::codec::{DecodeError, Reader, Writer};

/// ComputePool op namespace (#217 A2): op discriminants are `0xC100 | op`.
pub const COMPUTE_POOL_OP_NAMESPACE: u16 = 0xC100;

// Reserved (deferred, not landed): create-job is blocked on a byte-complete
// graph/edge/derived-id codec; assign/reassign are beacon-dependent (#223). The
// op ids are held so the numbering stays stable when each carrier lands.
pub const OP_CREATE_JOB_RESERVED: u16 = COMPUTE_POOL_OP_NAMESPACE | 0x01;
pub const OP_PUBLISH_OFFER: u16 = COMPUTE_POOL_OP_NAMESPACE | 0x02;
pub const OP_ACCEPT_UNIT: u16 = COMPUTE_POOL_OP_NAMESPACE | 0x03;
pub const OP_DECLINE_UNIT: u16 = COMPUTE_POOL_OP_NAMESPACE | 0x04;
pub const OP_EXPIRE_UNIT: u16 = COMPUTE_POOL_OP_NAMESPACE | 0x05;
pub const OP_CANCEL_JOB: u16 = COMPUTE_POOL_OP_NAMESPACE | 0x06;
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
// 1. PublishBondedOfferV1
// ===========================================================================

/// Publish a bonded capacity offer. `offer_bond_id` is DERIVED at execution from
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

/// Accept an assigned work unit. References the assigned work item (full
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
// 5. CancelJobV1
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
    PublishOffer(PublishBondedOfferV1),
    AcceptUnit(AcceptWorkUnitV1),
    DeclineUnit(DeclineWorkUnitV1),
    ExpireUnit(ExpireWorkUnitV1),
    CancelJob(CancelJobV1),
}

impl ComputePoolOperation {
    pub fn op(&self) -> u16 {
        match self {
            ComputePoolOperation::PublishOffer(_) => OP_PUBLISH_OFFER,
            ComputePoolOperation::AcceptUnit(_) => OP_ACCEPT_UNIT,
            ComputePoolOperation::DeclineUnit(_) => OP_DECLINE_UNIT,
            ComputePoolOperation::ExpireUnit(_) => OP_EXPIRE_UNIT,
            ComputePoolOperation::CancelJob(_) => OP_CANCEL_JOB,
        }
    }

    pub fn try_encode(&self) -> Result<Vec<u8>, DecodeError> {
        match self {
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
        // Deferred (reserved, not landed): create-job (blocked on graph codec),
        // assign/reassign (beacon-dependent, #223).
        assert_eq!(OP_CREATE_JOB_RESERVED, 0xC101);
        assert_eq!(OP_ASSIGN_UNIT_RESERVED, 0xC107);
        assert_eq!(OP_REASSIGN_UNIT_RESERVED, 0xC108);
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
