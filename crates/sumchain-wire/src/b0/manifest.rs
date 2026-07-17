//! Output and input manifests + their 85-byte slot descriptors (plan §8/§9).
//!
//! Header is 38 bytes (`tag[32] · version u16 · slot_count u32`); each descriptor
//! is 85 bytes (`kind u8 · slot_index u32 · ObjectCommitmentV1[80]`). Slots must
//! be strictly ascending by `(kind, slot_index)`; the embedded commitment's
//! object kind must match the slot kind; `slot_count` is bounded before any
//! allocation.

use crate::b0::codec::{DecodeError, Reader, Writer};
use crate::b0::consts;
use crate::b0::enums::{InputSlotKind, ObjectKind, SlotKind};
use crate::b0::object_commitment::ObjectCommitmentV1;
use crate::b0::tags::{INPUT_MANIFEST_TAG, OUTPUT_MANIFEST_TAG};

pub const MANIFEST_VERSION: u16 = 1;
pub const MANIFEST_HEADER_LEN: usize = 38;
pub const SLOT_DESCRIPTOR_LEN: usize = 85;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlotDescriptorV1 {
    pub slot_kind: SlotKind,
    pub slot_index: u32,
    pub commitment: ObjectCommitmentV1,
}

impl SlotDescriptorV1 {
    fn encode_into(&self, w: &mut Writer) {
        w.u8(self.slot_kind.to_repr());
        w.u32(self.slot_index);
        w.bytes(&self.commitment.encode());
    }
    fn decode(r: &mut Reader) -> Result<Self, DecodeError> {
        let slot_kind = SlotKind::from_repr(r.read_u8("SlotDescriptorV1.slot_kind")?)?;
        let slot_index = r.read_u32("SlotDescriptorV1.slot_index")?;
        let commitment = ObjectCommitmentV1::decode_expecting(
            r,
            slot_kind.object_kind(),
            "SlotDescriptorV1.object_kind",
        )?;
        Ok(Self {
            slot_kind,
            slot_index,
            commitment,
        })
    }
    fn order_key(&self) -> (u8, u32) {
        (self.slot_kind.to_repr(), self.slot_index)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputSlotDescriptorV1 {
    pub slot_kind: InputSlotKind,
    pub slot_index: u32,
    pub commitment: ObjectCommitmentV1,
}

impl InputSlotDescriptorV1 {
    fn encode_into(&self, w: &mut Writer) {
        w.u8(self.slot_kind.to_repr());
        w.u32(self.slot_index);
        w.bytes(&self.commitment.encode());
    }
    fn decode(r: &mut Reader) -> Result<Self, DecodeError> {
        let slot_kind = InputSlotKind::from_repr(r.read_u8("InputSlotDescriptorV1.slot_kind")?)?;
        let slot_index = r.read_u32("InputSlotDescriptorV1.slot_index")?;
        let commitment = ObjectCommitmentV1::decode_expecting(
            r,
            slot_kind.object_kind(),
            "InputSlotDescriptorV1.object_kind",
        )?;
        Ok(Self {
            slot_kind,
            slot_index,
            commitment,
        })
    }
    fn order_key(&self) -> (u8, u32) {
        (self.slot_kind.to_repr(), self.slot_index)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputManifestV1 {
    pub slots: Vec<SlotDescriptorV1>,
}

impl OutputManifestV1 {
    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.tag(&OUTPUT_MANIFEST_TAG);
        w.u16(MANIFEST_VERSION);
        w.u32(self.slots.len() as u32);
        for s in &self.slots {
            s.encode_into(&mut w);
        }
        w.into_bytes()
    }

    /// Validate every frozen invariant the decoder enforces: the slot-count cap
    /// (which also proves the count fits its `u32` wire field), strict ascending
    /// `(slot_kind, slot_index)` order, uniqueness, and the slot-kind ↔ embedded
    /// object-kind relationship. A struct from `decode_exact` is valid by
    /// construction, so `decode → try_encode` round-trips.
    pub fn validate(&self) -> Result<(), DecodeError> {
        if self.slots.len() as u64 > consts::OUTPUT_MANIFEST_MAX_SLOTS as u64 {
            return Err(DecodeError::CountExceedsMax {
                ctx: "OutputManifestV1.slot_count",
                count: self.slots.len() as u64,
                max: consts::OUTPUT_MANIFEST_MAX_SLOTS as u64,
            });
        }
        let mut prev: Option<(u8, u32)> = None;
        for s in &self.slots {
            if s.commitment.object_kind() != s.slot_kind.object_kind() {
                return Err(DecodeError::Inconsistent {
                    ctx: "SlotDescriptorV1.object_kind",
                });
            }
            s.commitment.validate()?;
            let key = s.order_key();
            if let Some(p) = prev {
                if key == p {
                    return Err(DecodeError::DuplicateEntry {
                        ctx: "OutputManifestV1.slots",
                    });
                }
                if key < p {
                    return Err(DecodeError::NonCanonicalOrder {
                        ctx: "OutputManifestV1.slots",
                    });
                }
            }
            prev = Some(key);
        }
        Ok(())
    }

    /// `validate()` then encode: the only public way to obtain canonical bytes,
    /// so no public method emits or hashes a structure the decoder would reject.
    pub fn try_encode(&self) -> Result<Vec<u8>, DecodeError> {
        self.validate()?;
        Ok(self.encode())
    }

    /// Commit to the validated canonical bytes as an `OutputManifest` object.
    pub fn try_commitment(&self) -> Result<ObjectCommitmentV1, DecodeError> {
        ObjectCommitmentV1::commit(ObjectKind::OutputManifest, &self.try_encode()?)
    }

    pub fn decode(r: &mut Reader) -> Result<Self, DecodeError> {
        let tag = r.read_array::<32>("OutputManifestV1.tag")?;
        if tag != OUTPUT_MANIFEST_TAG {
            return Err(DecodeError::BadTag {
                ctx: "OutputManifestV1",
            });
        }
        let v = r.read_u16("OutputManifestV1.version")?;
        if v != MANIFEST_VERSION {
            return Err(DecodeError::BadFixedScalar {
                ctx: "OutputManifestV1.version",
                value: v as u64,
            });
        }
        let count = r.read_u32("OutputManifestV1.slot_count")?;
        if count > consts::OUTPUT_MANIFEST_MAX_SLOTS {
            return Err(DecodeError::CountExceedsMax {
                ctx: "OutputManifestV1.slot_count",
                count: count as u64,
                max: consts::OUTPUT_MANIFEST_MAX_SLOTS as u64,
            });
        }
        let mut slots = Vec::with_capacity(count as usize);
        let mut prev: Option<(u8, u32)> = None;
        for _ in 0..count {
            let s = SlotDescriptorV1::decode(r)?;
            let key = s.order_key();
            if let Some(p) = prev {
                if key == p {
                    return Err(DecodeError::DuplicateEntry {
                        ctx: "OutputManifestV1.slots",
                    });
                }
                if key < p {
                    return Err(DecodeError::NonCanonicalOrder {
                        ctx: "OutputManifestV1.slots",
                    });
                }
            }
            prev = Some(key);
            slots.push(s);
        }
        Ok(Self { slots })
    }

    pub fn decode_exact(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let v = Self::decode(&mut r)?;
        r.finish("OutputManifestV1")?;
        Ok(v)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputManifestV1 {
    pub slots: Vec<InputSlotDescriptorV1>,
}

impl InputManifestV1 {
    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.tag(&INPUT_MANIFEST_TAG);
        w.u16(MANIFEST_VERSION);
        w.u32(self.slots.len() as u32);
        for s in &self.slots {
            s.encode_into(&mut w);
        }
        w.into_bytes()
    }

    /// Validate every frozen invariant the decoder enforces: the slot-count cap
    /// (which also proves the count fits its `u32` wire field), strict ascending
    /// `(slot_kind, slot_index)` order, uniqueness, and the slot-kind ↔ embedded
    /// object-kind relationship. A struct from `decode_exact` is valid by
    /// construction, so `decode → try_encode` round-trips.
    pub fn validate(&self) -> Result<(), DecodeError> {
        if self.slots.len() as u64 > consts::INPUT_MANIFEST_MAX_SLOTS as u64 {
            return Err(DecodeError::CountExceedsMax {
                ctx: "InputManifestV1.slot_count",
                count: self.slots.len() as u64,
                max: consts::INPUT_MANIFEST_MAX_SLOTS as u64,
            });
        }
        let mut prev: Option<(u8, u32)> = None;
        for s in &self.slots {
            if s.commitment.object_kind() != s.slot_kind.object_kind() {
                return Err(DecodeError::Inconsistent {
                    ctx: "InputSlotDescriptorV1.object_kind",
                });
            }
            s.commitment.validate()?;
            let key = s.order_key();
            if let Some(p) = prev {
                if key == p {
                    return Err(DecodeError::DuplicateEntry {
                        ctx: "InputManifestV1.slots",
                    });
                }
                if key < p {
                    return Err(DecodeError::NonCanonicalOrder {
                        ctx: "InputManifestV1.slots",
                    });
                }
            }
            prev = Some(key);
        }
        Ok(())
    }

    /// `validate()` then encode: the only public way to obtain canonical bytes,
    /// so no public method emits or hashes a structure the decoder would reject.
    pub fn try_encode(&self) -> Result<Vec<u8>, DecodeError> {
        self.validate()?;
        Ok(self.encode())
    }

    /// Commit to the validated canonical bytes as an `InputManifest` object.
    pub fn try_commitment(&self) -> Result<ObjectCommitmentV1, DecodeError> {
        ObjectCommitmentV1::commit(ObjectKind::InputManifest, &self.try_encode()?)
    }

    pub fn decode(r: &mut Reader) -> Result<Self, DecodeError> {
        let tag = r.read_array::<32>("InputManifestV1.tag")?;
        if tag != INPUT_MANIFEST_TAG {
            return Err(DecodeError::BadTag {
                ctx: "InputManifestV1",
            });
        }
        let v = r.read_u16("InputManifestV1.version")?;
        if v != MANIFEST_VERSION {
            return Err(DecodeError::BadFixedScalar {
                ctx: "InputManifestV1.version",
                value: v as u64,
            });
        }
        let count = r.read_u32("InputManifestV1.slot_count")?;
        if count > consts::INPUT_MANIFEST_MAX_SLOTS {
            return Err(DecodeError::CountExceedsMax {
                ctx: "InputManifestV1.slot_count",
                count: count as u64,
                max: consts::INPUT_MANIFEST_MAX_SLOTS as u64,
            });
        }
        let mut slots = Vec::with_capacity(count as usize);
        let mut prev: Option<(u8, u32)> = None;
        for _ in 0..count {
            let s = InputSlotDescriptorV1::decode(r)?;
            let key = s.order_key();
            if let Some(p) = prev {
                if key == p {
                    return Err(DecodeError::DuplicateEntry {
                        ctx: "InputManifestV1.slots",
                    });
                }
                if key < p {
                    return Err(DecodeError::NonCanonicalOrder {
                        ctx: "InputManifestV1.slots",
                    });
                }
            }
            prev = Some(key);
            slots.push(s);
        }
        Ok(Self { slots })
    }

    pub fn decode_exact(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let v = Self::decode(&mut r)?;
        r.finish("InputManifestV1")?;
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn res_slot(idx: u32) -> SlotDescriptorV1 {
        SlotDescriptorV1 {
            slot_kind: SlotKind::ResidualStream,
            slot_index: idx,
            commitment: ObjectCommitmentV1::commit(ObjectKind::ResidualState, b"r").unwrap(),
        }
    }
    fn kv_slot(idx: u32) -> SlotDescriptorV1 {
        SlotDescriptorV1 {
            slot_kind: SlotKind::KvCache,
            slot_index: idx,
            commitment: ObjectCommitmentV1::commit(ObjectKind::KvState, b"k").unwrap(),
        }
    }

    #[test]
    fn descriptor_and_header_sizes() {
        // header 38 = tag(32)+version(2)+count(4); descriptor 85 = 1+4+80
        let empty = OutputManifestV1 { slots: vec![] };
        assert_eq!(empty.encode().len(), 38);
        let two = OutputManifestV1 {
            slots: vec![res_slot(7), kv_slot(7)],
        };
        assert_eq!(two.encode().len(), 38 + 2 * 85); // 208
        let three_input = InputManifestV1 {
            slots: vec![
                InputSlotDescriptorV1 {
                    slot_kind: InputSlotKind::PriorResidual,
                    slot_index: 0,
                    commitment: ObjectCommitmentV1::commit(ObjectKind::PriorResidual, b"a")
                        .unwrap(),
                },
                InputSlotDescriptorV1 {
                    slot_kind: InputSlotKind::PriorKv,
                    slot_index: 0,
                    commitment: ObjectCommitmentV1::commit(ObjectKind::PriorKv, b"b").unwrap(),
                },
                InputSlotDescriptorV1 {
                    slot_kind: InputSlotKind::TokenPrefix,
                    slot_index: 0,
                    commitment: ObjectCommitmentV1::commit(ObjectKind::TokenPrefix, b"c").unwrap(),
                },
            ],
        };
        assert_eq!(three_input.encode().len(), 38 + 3 * 85); // 293
    }

    #[test]
    fn output_manifest_roundtrips() {
        let m = OutputManifestV1 {
            slots: vec![res_slot(7), kv_slot(7)],
        };
        assert_eq!(OutputManifestV1::decode_exact(&m.encode()).unwrap(), m);
    }

    #[test]
    fn descending_order_rejected() {
        // kv(kind 1) before residual(kind 0) is descending on kind
        let m = OutputManifestV1 {
            slots: vec![kv_slot(7), res_slot(7)],
        };
        assert!(matches!(
            OutputManifestV1::decode_exact(&m.encode()),
            Err(DecodeError::NonCanonicalOrder { .. })
        ));
    }

    #[test]
    fn duplicate_slot_rejected() {
        let m = OutputManifestV1 {
            slots: vec![res_slot(7), res_slot(7)],
        };
        assert!(matches!(
            OutputManifestV1::decode_exact(&m.encode()),
            Err(DecodeError::DuplicateEntry { .. })
        ));
    }

    #[test]
    fn count_over_max_rejected_before_body() {
        // header claims 300 slots (> 256) with no body: rejected on the count,
        // not by running off the end.
        let mut w = Writer::new();
        w.tag(&OUTPUT_MANIFEST_TAG);
        w.u16(MANIFEST_VERSION);
        w.u32(300);
        assert!(matches!(
            OutputManifestV1::decode_exact(&w.into_bytes()),
            Err(DecodeError::CountExceedsMax { .. })
        ));
    }

    #[test]
    fn input_manifest_count_over_eight_rejected() {
        let mut w = Writer::new();
        w.tag(&INPUT_MANIFEST_TAG);
        w.u16(MANIFEST_VERSION);
        w.u32(9);
        assert!(matches!(
            InputManifestV1::decode_exact(&w.into_bytes()),
            Err(DecodeError::CountExceedsMax { .. })
        ));
    }

    #[test]
    fn slot_object_kind_mismatch_rejected() {
        // ResidualStream slot embedding a KvState commitment
        let bad = SlotDescriptorV1 {
            slot_kind: SlotKind::ResidualStream,
            slot_index: 0,
            commitment: ObjectCommitmentV1::commit(ObjectKind::KvState, b"x").unwrap(),
        };
        let m = OutputManifestV1 { slots: vec![bad] };
        assert!(matches!(
            OutputManifestV1::decode_exact(&m.encode()),
            Err(DecodeError::Inconsistent {
                ctx: "SlotDescriptorV1.object_kind"
            })
        ));
    }

    // ---- Design B: the construction/encoding path also fails closed ----

    #[test]
    fn try_commitment_ok_for_valid_manifest() {
        let m = OutputManifestV1 {
            slots: vec![res_slot(7), kv_slot(7)],
        };
        assert!(m.validate().is_ok());
        assert_eq!(m.try_encode().unwrap().len(), 38 + 2 * 85);
        assert_eq!(
            m.try_commitment().unwrap().object_kind(),
            ObjectKind::OutputManifest
        );
    }

    #[test]
    fn try_encode_rejects_unsorted_slots() {
        let m = OutputManifestV1 {
            slots: vec![kv_slot(7), res_slot(7)],
        };
        assert!(matches!(
            m.try_encode(),
            Err(DecodeError::NonCanonicalOrder { .. })
        ));
        assert!(matches!(
            m.try_commitment(),
            Err(DecodeError::NonCanonicalOrder { .. })
        ));
    }

    #[test]
    fn try_encode_rejects_duplicate_slots() {
        let m = OutputManifestV1 {
            slots: vec![res_slot(7), res_slot(7)],
        };
        assert!(matches!(
            m.try_encode(),
            Err(DecodeError::DuplicateEntry { .. })
        ));
    }

    #[test]
    fn try_encode_rejects_slot_object_kind_mismatch() {
        let bad = SlotDescriptorV1 {
            slot_kind: SlotKind::ResidualStream,
            slot_index: 0,
            commitment: ObjectCommitmentV1::commit(ObjectKind::KvState, b"x").unwrap(),
        };
        let m = OutputManifestV1 { slots: vec![bad] };
        assert!(matches!(
            m.try_encode(),
            Err(DecodeError::Inconsistent {
                ctx: "SlotDescriptorV1.object_kind"
            })
        ));
    }

    #[test]
    fn try_encode_rejects_over_cap_input_manifest() {
        // 9 input slots > INPUT_MANIFEST_MAX_SLOTS (8): the count cap fires first.
        let slots: Vec<_> = (0..9)
            .map(|i| InputSlotDescriptorV1 {
                slot_kind: InputSlotKind::PriorResidual,
                slot_index: i,
                commitment: ObjectCommitmentV1::commit(ObjectKind::PriorResidual, b"a").unwrap(),
            })
            .collect();
        let m = InputManifestV1 { slots };
        assert!(matches!(
            m.try_encode(),
            Err(DecodeError::CountExceedsMax { .. })
        ));
    }

    // ---- transitive: a lying embedded commitment is rejected at the manifest
    // decode layer (fed as bytes no ObjectCommitmentV1 constructor could produce) ----

    fn raw_commitment(
        kind: ObjectKind,
        byte_len: u64,
        chunk_count: u32,
        root: [u8; 32],
    ) -> Vec<u8> {
        let mut w = Writer::new();
        w.tag(&crate::b0::tags::OBJECT_TAG);
        w.u16(ObjectCommitmentV1::SCHEMA_VERSION);
        w.u16(kind.to_repr());
        w.u64(byte_len);
        w.u32(chunk_count);
        w.bytes(&root);
        w.into_bytes()
    }

    fn output_manifest_bytes(slot_kind: SlotKind, slot_index: u32, commitment: &[u8]) -> Vec<u8> {
        let mut w = Writer::new();
        w.tag(&OUTPUT_MANIFEST_TAG);
        w.u16(MANIFEST_VERSION);
        w.u32(1);
        w.u8(slot_kind.to_repr());
        w.u32(slot_index);
        w.bytes(commitment);
        w.into_bytes()
    }

    #[test]
    fn embedded_lying_chunk_count_rejected_at_manifest_decode() {
        // A ResidualState commitment claiming 4 chunks for a 3-chunk byte_len.
        let three = 3u64 * crate::b0::merkle::CHUNK as u64;
        let c = raw_commitment(ObjectKind::ResidualState, three, 4, [9u8; 32]);
        let bytes = output_manifest_bytes(SlotKind::ResidualStream, 0, &c);
        assert!(matches!(
            OutputManifestV1::decode_exact(&bytes),
            Err(DecodeError::Inconsistent {
                ctx: "ObjectCommitmentV1.chunk_count"
            })
        ));
    }

    #[test]
    fn embedded_empty_object_nonzero_root_rejected_at_manifest_decode() {
        // byte_len 0 (chunk_count 0) but a nonzero Merkle root.
        let c = raw_commitment(ObjectKind::ResidualState, 0, 0, [1u8; 32]);
        let bytes = output_manifest_bytes(SlotKind::ResidualStream, 0, &c);
        assert!(matches!(
            OutputManifestV1::decode_exact(&bytes),
            Err(DecodeError::Inconsistent {
                ctx: "ObjectCommitmentV1.empty_root"
            })
        ));
    }

    #[test]
    fn embedded_unrepresentable_chunk_count_rejected_at_manifest_decode() {
        let huge = u32::MAX as u64 * crate::b0::merkle::CHUNK as u64 + 1;
        let c = raw_commitment(ObjectKind::ResidualState, huge, 0, [0u8; 32]);
        let bytes = output_manifest_bytes(SlotKind::ResidualStream, 0, &c);
        assert!(matches!(
            OutputManifestV1::decode_exact(&bytes),
            Err(DecodeError::CountExceedsMax {
                ctx: "merkle.chunk_count",
                ..
            })
        ));
    }

    #[test]
    fn embedded_wrong_object_kind_rejected_before_encode_or_hash() {
        // A valid but WRONG-KIND commitment: the canonical routes reject before
        // emitting or hashing anything.
        let bad = SlotDescriptorV1 {
            slot_kind: SlotKind::ResidualStream,
            slot_index: 0,
            commitment: ObjectCommitmentV1::commit(ObjectKind::KvState, b"x").unwrap(),
        };
        let m = OutputManifestV1 { slots: vec![bad] };
        assert!(matches!(
            m.try_encode(),
            Err(DecodeError::Inconsistent {
                ctx: "SlotDescriptorV1.object_kind"
            })
        ));
        assert!(matches!(
            m.try_commitment(),
            Err(DecodeError::Inconsistent {
                ctx: "SlotDescriptorV1.object_kind"
            })
        ));
        // the raw bytes are likewise rejected by the decoder
        assert!(OutputManifestV1::decode_exact(&m.encode()).is_err());
    }
}
