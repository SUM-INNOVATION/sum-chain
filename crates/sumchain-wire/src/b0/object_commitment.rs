//! `ObjectCommitmentV1` — 80 bytes (plan §8).
//!
//! Layout: `OBJECT[32] · schema_version u16 · object_kind u16 · byte_len u64 ·
//! chunk_count u32 · merkle_root[32]`.

use crate::b0::codec::{DecodeError, Reader, Writer};
use crate::b0::enums::ObjectKind;
use crate::b0::merkle;
use crate::b0::tags::OBJECT_TAG;

/// Object kind, byte length, chunk count, and SNIP Merkle root of a committed
/// object.
///
/// Fields are **private**; the only constructors are the checked
/// [`commit`](Self::commit), [`empty`](Self::empty), and the decoders, so an
/// `ObjectCommitmentV1` value can never hold decoder-inconsistent state. Because
/// invalid state is unrepresentable, `encode`/`identity` stay infallible (they can
/// only ever observe a valid value), which transitively closes canonicality for
/// every container that embeds one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectCommitmentV1 {
    object_kind: ObjectKind,
    byte_len: u64,
    chunk_count: u32,
    merkle_root: [u8; 32],
}

impl ObjectCommitmentV1 {
    pub const SCHEMA_VERSION: u16 = 1;
    /// Documented total, used by containing structures for offset arithmetic.
    /// Tests assert the *encoder-derived* length against the literal 80.
    pub const LEN: usize = 80;

    /// Commit to `data` as an object of `kind`.
    ///
    /// Fallible: `data.len()` is checked into `u64` and the chunk count is
    /// checked against `u32::MAX` (via [`merkle::chunk_count_checked`]), so no
    /// release build can truncate an unrepresentable length into a valid-looking
    /// commitment.
    pub fn commit(kind: ObjectKind, data: &[u8]) -> Result<Self, DecodeError> {
        let byte_len = u64::try_from(data.len()).map_err(|_| DecodeError::BadValue {
            ctx: "ObjectCommitmentV1.data_len",
        })?;
        Ok(Self {
            object_kind: kind,
            byte_len,
            chunk_count: merkle::chunk_count_checked(byte_len)?,
            merkle_root: merkle::merkle_root(data),
        })
    }

    /// The canonical empty commitment for `kind` (`byte_len=0`, zero root).
    pub fn empty(kind: ObjectKind) -> Self {
        Self {
            object_kind: kind,
            byte_len: 0,
            chunk_count: 0,
            merkle_root: [0u8; 32],
        }
    }

    /// The object kind this commitment is for.
    pub fn object_kind(&self) -> ObjectKind {
        self.object_kind
    }
    /// The committed object's byte length.
    pub fn byte_len(&self) -> u64 {
        self.byte_len
    }
    /// The committed object's chunk count (`ceil(byte_len / CHUNK)`).
    pub fn chunk_count(&self) -> u32 {
        self.chunk_count
    }
    /// The SNIP Merkle root over the object's 1 MiB chunks.
    pub fn merkle_root(&self) -> [u8; 32] {
        self.merkle_root
    }

    /// Re-check the invariants a decoded commitment satisfies: the chunk count is
    /// representable and equals `ceil(byte_len / CHUNK)`, and an empty object has
    /// the zero root. Always `Ok` for a value from a constructor (they establish
    /// these), exposed so containers can assert embedded commitments defensively.
    pub fn validate(&self) -> Result<(), DecodeError> {
        if self.chunk_count != merkle::chunk_count_checked(self.byte_len)? {
            return Err(DecodeError::Inconsistent {
                ctx: "ObjectCommitmentV1.chunk_count",
            });
        }
        if self.byte_len == 0 && self.merkle_root != [0u8; 32] {
            return Err(DecodeError::Inconsistent {
                ctx: "ObjectCommitmentV1.empty_root",
            });
        }
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.tag(&OBJECT_TAG);
        w.u16(Self::SCHEMA_VERSION);
        w.u16(self.object_kind.to_repr());
        w.u64(self.byte_len);
        w.u32(self.chunk_count);
        w.bytes(&self.merkle_root);
        w.into_bytes()
    }

    /// `identity(ObjectCommitmentV1) = BLAKE3(its 80 canonical bytes)`.
    pub fn identity(&self) -> [u8; 32] {
        blake3::hash(&self.encode()).into()
    }

    /// Decode from a reader, validating tag, schema version, kind, and the
    /// `chunk_count == ceil(byte_len/CHUNK)` / empty-root invariants.
    pub fn decode(r: &mut Reader) -> Result<Self, DecodeError> {
        let tag = r.read_array::<32>("ObjectCommitmentV1.tag")?;
        if tag != OBJECT_TAG {
            return Err(DecodeError::BadTag {
                ctx: "ObjectCommitmentV1",
            });
        }
        let sv = r.read_u16("ObjectCommitmentV1.schema_version")?;
        if sv != Self::SCHEMA_VERSION {
            return Err(DecodeError::BadFixedScalar {
                ctx: "ObjectCommitmentV1.schema_version",
                value: sv as u64,
            });
        }
        let object_kind = ObjectKind::from_repr(r.read_u16("ObjectCommitmentV1.object_kind")?)?;
        let byte_len = r.read_u64("ObjectCommitmentV1.byte_len")?;
        let chunk_count = r.read_u32("ObjectCommitmentV1.chunk_count")?;
        let merkle_root = r.read_array::<32>("ObjectCommitmentV1.merkle_root")?;

        if chunk_count != merkle::chunk_count_checked(byte_len)? {
            return Err(DecodeError::Inconsistent {
                ctx: "ObjectCommitmentV1.chunk_count",
            });
        }
        if byte_len == 0 && merkle_root != [0u8; 32] {
            return Err(DecodeError::Inconsistent {
                ctx: "ObjectCommitmentV1.empty_root",
            });
        }
        Ok(Self {
            object_kind,
            byte_len,
            chunk_count,
            merkle_root,
        })
    }

    /// Decode consuming exactly `bytes` (rejects trailing).
    pub fn decode_exact(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let v = Self::decode(&mut r)?;
        r.finish("ObjectCommitmentV1")?;
        Ok(v)
    }

    /// Decode an embedded commitment that must carry a specific object kind.
    pub fn decode_expecting(
        r: &mut Reader,
        expected: ObjectKind,
        ctx: &'static str,
    ) -> Result<Self, DecodeError> {
        let v = Self::decode(r)?;
        if v.object_kind != expected {
            return Err(DecodeError::Inconsistent { ctx });
        }
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoded_length_is_eighty() {
        let c = ObjectCommitmentV1::commit(ObjectKind::Model, &[7u8; 100]).unwrap();
        assert_eq!(c.encode().len(), 80);
    }

    #[test]
    fn roundtrips_for_several_kinds() {
        for kind in [
            ObjectKind::Model,
            ObjectKind::TokenPrefix,
            ObjectKind::KvState,
        ] {
            let c = ObjectCommitmentV1::commit(kind, b"payload bytes").unwrap();
            let back = ObjectCommitmentV1::decode_exact(&c.encode()).unwrap();
            assert_eq!(back, c);
        }
    }

    #[test]
    fn empty_commitment_roundtrips_and_bad_empty_root_rejected() {
        let e = ObjectCommitmentV1::empty(ObjectKind::PriorKv);
        assert_eq!(e.chunk_count(), 0);
        assert_eq!(e.merkle_root(), [0u8; 32]);
        assert_eq!(ObjectCommitmentV1::decode_exact(&e.encode()).unwrap(), e);

        // byte_len=0 but non-zero root is inconsistent
        let mut bytes = e.encode();
        bytes[48] = 0x01; // first byte of merkle_root
        assert!(matches!(
            ObjectCommitmentV1::decode_exact(&bytes),
            Err(DecodeError::Inconsistent {
                ctx: "ObjectCommitmentV1.empty_root"
            })
        ));
    }

    #[test]
    fn chunk_count_ambiguity_is_closed() {
        // A commitment claiming 3 chunks by byte_len but 4 by chunk_count is
        // rejected — this is what defeats the duplicated-4th-leaf forgery.
        let three_chunks = 3u64 * merkle::CHUNK as u64;
        let mut w = Writer::new();
        w.tag(&OBJECT_TAG);
        w.u16(ObjectCommitmentV1::SCHEMA_VERSION);
        w.u16(ObjectKind::ResidualState.to_repr());
        w.u64(three_chunks);
        w.u32(4); // lie: real count is 3
        w.bytes(&[9u8; 32]);
        assert!(matches!(
            ObjectCommitmentV1::decode_exact(&w.into_bytes()),
            Err(DecodeError::Inconsistent {
                ctx: "ObjectCommitmentV1.chunk_count"
            })
        ));
    }

    #[test]
    fn decode_rejects_unrepresentable_chunk_count() {
        // A byte_len needing u32::MAX + 1 chunks is rejected while computing the
        // expected count — a release build never truncates it into a match.
        let byte_len = u32::MAX as u64 * merkle::CHUNK as u64 + 1;
        let mut w = Writer::new();
        w.tag(&OBJECT_TAG);
        w.u16(ObjectCommitmentV1::SCHEMA_VERSION);
        w.u16(ObjectKind::ResidualState.to_repr());
        w.u64(byte_len);
        w.u32(0); // any claimed count; decode fails computing the expected one
        w.bytes(&[0u8; 32]);
        assert!(matches!(
            ObjectCommitmentV1::decode_exact(&w.into_bytes()),
            Err(DecodeError::CountExceedsMax {
                ctx: "merkle.chunk_count",
                ..
            })
        ));
    }

    #[test]
    fn object_kind_mismatch_rejected() {
        let c = ObjectCommitmentV1::commit(ObjectKind::TokenSeq, b"abc").unwrap();
        let bytes = c.encode();
        let mut r = Reader::new(&bytes);
        assert!(matches!(
            ObjectCommitmentV1::decode_expecting(&mut r, ObjectKind::Model, "expect-model"),
            Err(DecodeError::Inconsistent {
                ctx: "expect-model"
            })
        ));
    }

    #[test]
    fn reserved_kind_in_bytes_rejected() {
        let c = ObjectCommitmentV1::commit(ObjectKind::Model, b"abc").unwrap();
        let mut bytes = c.encode();
        bytes[34..36].copy_from_slice(&2u16.to_le_bytes()); // object_kind = reserved Tokenizer(2)
        assert!(matches!(
            ObjectCommitmentV1::decode_exact(&bytes),
            Err(DecodeError::ReservedEnum {
                name: "ObjectKind",
                value: 2
            })
        ));
    }

    #[test]
    fn bad_tag_rejected() {
        let c = ObjectCommitmentV1::commit(ObjectKind::Model, b"abc").unwrap();
        let mut bytes = c.encode();
        bytes[0] ^= 0xFF;
        assert!(matches!(
            ObjectCommitmentV1::decode_exact(&bytes),
            Err(DecodeError::BadTag { .. })
        ));
    }

    #[test]
    fn truncation_and_trailing_rejected() {
        let c = ObjectCommitmentV1::commit(ObjectKind::Model, b"abc").unwrap();
        let bytes = c.encode();
        assert!(matches!(
            ObjectCommitmentV1::decode_exact(&bytes[..79]),
            Err(DecodeError::Truncated { .. })
        ));
        let mut too_long = bytes.clone();
        too_long.push(0x00);
        assert!(matches!(
            ObjectCommitmentV1::decode_exact(&too_long),
            Err(DecodeError::TrailingBytes { .. })
        ));
    }
}
