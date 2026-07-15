//! Output and input manifests + their 85-byte slot descriptors (plan §8/§9).
//!
//! Header is 38 bytes (`tag[32] · version u16 · slot_count u32`); each descriptor
//! is 85 bytes (`kind u8 · slot_index u32 · ObjectCommitmentV1[80]`). Slots must
//! be strictly ascending by `(kind, slot_index)`; the embedded commitment's
//! object kind must match the slot kind; `slot_count` is bounded before any
//! allocation.

use crate::codec::{DecodeError, Reader, Writer};
use crate::consts;
use crate::enums::{InputSlotKind, ObjectKind, SlotKind};
use crate::schema::object::ObjectCommitmentV1;
use crate::tags::{INPUT_MANIFEST_TAG, OUTPUT_MANIFEST_TAG};

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
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.tag(&OUTPUT_MANIFEST_TAG);
        w.u16(MANIFEST_VERSION);
        w.u32(self.slots.len() as u32);
        for s in &self.slots {
            s.encode_into(&mut w);
        }
        w.into_bytes()
    }

    pub fn commitment(&self) -> ObjectCommitmentV1 {
        ObjectCommitmentV1::commit(ObjectKind::OutputManifest, &self.encode())
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
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.tag(&INPUT_MANIFEST_TAG);
        w.u16(MANIFEST_VERSION);
        w.u32(self.slots.len() as u32);
        for s in &self.slots {
            s.encode_into(&mut w);
        }
        w.into_bytes()
    }

    pub fn commitment(&self) -> ObjectCommitmentV1 {
        ObjectCommitmentV1::commit(ObjectKind::InputManifest, &self.encode())
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
            commitment: ObjectCommitmentV1::commit(ObjectKind::ResidualState, b"r"),
        }
    }
    fn kv_slot(idx: u32) -> SlotDescriptorV1 {
        SlotDescriptorV1 {
            slot_kind: SlotKind::KvCache,
            slot_index: idx,
            commitment: ObjectCommitmentV1::commit(ObjectKind::KvState, b"k"),
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
                    commitment: ObjectCommitmentV1::commit(ObjectKind::PriorResidual, b"a"),
                },
                InputSlotDescriptorV1 {
                    slot_kind: InputSlotKind::PriorKv,
                    slot_index: 0,
                    commitment: ObjectCommitmentV1::commit(ObjectKind::PriorKv, b"b"),
                },
                InputSlotDescriptorV1 {
                    slot_kind: InputSlotKind::TokenPrefix,
                    slot_index: 0,
                    commitment: ObjectCommitmentV1::commit(ObjectKind::TokenPrefix, b"c"),
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
            commitment: ObjectCommitmentV1::commit(ObjectKind::KvState, b"x"),
        };
        let m = OutputManifestV1 { slots: vec![bad] };
        assert!(matches!(
            OutputManifestV1::decode_exact(&m.encode()),
            Err(DecodeError::Inconsistent {
                ctx: "SlotDescriptorV1.object_kind"
            })
        ));
    }
}
