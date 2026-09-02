//! C5 registry wire — content-derived registry identifiers (#128 / #217).
//!
//! DORMANT: this module defines consensus BYTES only. No registry transaction
//! ordinal and no registry activation gate are introduced (owner directive
//! 2026-09-02 — do not invent registry ordinal 30 or a registry gate). These
//! identifiers are the frozen building blocks a future registry mechanism will
//! reuse.
//!
//! All ids follow the frozen `BLAKE3(domain_tag ‖ fields)` convention
//! ([`crate::b0::hashing::prefixed`]). The registry family uses **NUL-terminated
//! (`\0`) variable-length domain tags** — ratified by the owner for
//! `tokenizer_id` (#217 B2) and standardized across the family (`vk_id`,
//! `graph_definition_root`) for consistency. Little-endian scalars, matching the
//! b0 codec.
//!
//! Ratified basis (#217): B2 keeps `ObjectKind::Tokenizer = 2` reserved-and-
//! rejected — tokenizers are identified WITHOUT an `ObjectKind`, by an opaque
//! domain-separated hash. B5 allocates NO new `ObjectKind`; the graph root is a
//! domain-separated hash whose *canonical graph encoding* is frozen separately
//! before it is used (see [`graph_definition_root`]).

use crate::b0::codec::{DecodeError, Reader, Writer};
use crate::b0::hashing::prefixed;

/// Domain tag for verifier-key ids. `\0`-terminated (registry family).
pub const VK_ID_TAG: &[u8] = b"SUMCHAIN/REGISTRY/VK/v1\0";
/// Domain tag for tokenizer ids. `\0`-terminated (owner-ratified, #217 B2).
pub const TOKENIZER_ID_TAG: &[u8] = b"SUMCHAIN/REGISTRY/TOKENIZER/v1\0";
/// Domain tag for graph-definition roots. `\0`-terminated (registry family).
pub const GRAPH_DEFINITION_TAG: &[u8] = b"SUMCHAIN/REGISTRY/GRAPHDEF/v1\0";

/// `vk_id = BLAKE3(VK_ID_TAG ‖ verifier_material_manifest_hash[32] ‖ u16_le(proof_system_id))`
/// (#217 B3).
///
/// Binds a verifier-key's material manifest to the proof system it verifies, so
/// the same VK material registered under two proof systems yields two distinct
/// ids (prevents cross-proof-system VK reuse). The `proof_system_id` is written
/// little-endian, matching every other b0/registry scalar.
pub fn vk_id(verifier_material_manifest_hash: &[u8; 32], proof_system_id: u16) -> [u8; 32] {
    let mut data = [0u8; 34];
    data[..32].copy_from_slice(verifier_material_manifest_hash);
    data[32..].copy_from_slice(&proof_system_id.to_le_bytes());
    prefixed(VK_ID_TAG, &data)
}

/// `tokenizer_id = BLAKE3(TOKENIZER_ID_TAG ‖ canonical_tokenizer_bytes)` (#217 B2).
///
/// Opaque, domain-separated tokenizer identity. `ObjectKind::Tokenizer = 2`
/// stays frozen reserved-and-rejected; tokenizers are NOT `ObjectCommitment`s.
/// `canonical_tokenizer_bytes` is the registrant's already-canonicalized encoding
/// (its canonicalization is out of scope for this id — the id only domain-binds
/// whatever bytes are presented).
pub fn tokenizer_id(canonical_tokenizer_bytes: &[u8]) -> [u8; 32] {
    prefixed(TOKENIZER_ID_TAG, canonical_tokenizer_bytes)
}

/// `graph_definition_root = BLAKE3(GRAPH_DEFINITION_TAG ‖ canonical_graph_encoding)`
/// (#217 B5).
///
/// A domain-separated root over a graph definition, allocating NO `ObjectKind`.
///
/// NOTE (frozen-before-use): the *canonical graph encoding* fed as
/// `canonical_graph_encoding` is NOT frozen in this module and must be frozen as
/// an explicit byte table (with its own vectors) before any consumer derives a
/// graph root for consensus. This function only fixes the domain-separation
/// wrapper, exactly as the owner directed (B5).
pub fn graph_definition_root(canonical_graph_encoding: &[u8]) -> [u8; 32] {
    prefixed(GRAPH_DEFINITION_TAG, canonical_graph_encoding)
}

/// Lifecycle status of a registry record (GovAsset-style, #217 A5).
///
/// The *transitions* (register → Enabled, disable → Disabled) and the quorum /
/// timelock that authorize them are governance concerns; this enum only fixes
/// the on-wire discriminant. Unknown discriminants are rejected on decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistryStatus {
    Enabled = 0,
    Disabled = 1,
}

impl RegistryStatus {
    pub fn to_u8(self) -> u8 {
        self as u8
    }
    pub fn from_u8(v: u8, ctx: &'static str) -> Result<Self, DecodeError> {
        match v {
            0 => Ok(Self::Enabled),
            1 => Ok(Self::Disabled),
            _ => Err(DecodeError::BadValue { ctx }),
        }
    }
}

/// C5 registry record — the on-wire provenance record for a registered
/// verifier-key / model (#128 / #217 A4 + B1). DORMANT: bytes only.
///
/// Layout (154 bytes, all scalars little-endian):
/// ```text
///   MAGIC[7] = "RREGv1\0"
///   schema_version        u16   (= 1)
///   id                    [32]  (content id, e.g. vk_id / model_commitment)
///   proof_system_id       u16
///   audit_commitment      [32]  ┐
///   source_commitment     [32]  ├ all THREE MANDATORY (#217 B1, ratified)
///   ceremony_commitment   [32]  ┘
///   verifier_binary_version u32
///   activation_height     u64   ┐ governance VALUES (deferred, #217 B6):
///   status                u8    │ carried as the type surface; the meaningful
///   approval_threshold_bps u16  ┘ values are set at the activation event
/// ```
///
/// The three provenance commitments are fixed-width and MANDATORY — there is no
/// presence flag, so the record cannot be encoded without them (fail-closed
/// provenance). Range/policy validation of `approval_threshold_bps` /
/// `activation_height` is a governance-layer concern, not a wire invariant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistryRecordV1 {
    pub id: [u8; 32],
    pub proof_system_id: u16,
    pub audit_commitment: [u8; 32],
    pub source_commitment: [u8; 32],
    pub ceremony_commitment: [u8; 32],
    pub verifier_binary_version: u32,
    pub activation_height: u64,
    pub status: RegistryStatus,
    pub approval_threshold_bps: u16,
}

impl RegistryRecordV1 {
    pub const MAGIC: [u8; 7] = *b"RREGv1\0";
    pub const SCHEMA_VERSION: u16 = 1;
    pub const LEN: usize = 7 + 2 + 32 + 2 + 32 + 32 + 32 + 4 + 8 + 1 + 2; // 154

    /// Structural re-check. The three mandatory commitments are fixed-width and
    /// thus always present at the byte level; there is no wire-level invariant
    /// beyond a well-formed `status` (enforced by the decoder). Kept for
    /// symmetry with the `beacon_wire` template and future invariants.
    pub fn validate(&self) -> Result<(), DecodeError> {
        Ok(())
    }

    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(&Self::MAGIC);
        w.u16(Self::SCHEMA_VERSION);
        w.bytes(&self.id);
        w.u16(self.proof_system_id);
        w.bytes(&self.audit_commitment);
        w.bytes(&self.source_commitment);
        w.bytes(&self.ceremony_commitment);
        w.u32(self.verifier_binary_version);
        w.u64(self.activation_height);
        w.u8(self.status.to_u8());
        w.u16(self.approval_threshold_bps);
        w.into_bytes()
    }

    pub fn try_encode(&self) -> Result<Vec<u8>, DecodeError> {
        self.validate()?;
        Ok(self.encode())
    }

    pub fn decode(r: &mut Reader) -> Result<Self, DecodeError> {
        let magic = r.read_array::<7>("RegistryRecordV1.magic")?;
        if magic != Self::MAGIC {
            return Err(DecodeError::BadTag {
                ctx: "RegistryRecordV1",
            });
        }
        let sv = r.read_u16("RegistryRecordV1.schema_version")?;
        if sv != Self::SCHEMA_VERSION {
            return Err(DecodeError::BadFixedScalar {
                ctx: "RegistryRecordV1.schema_version",
                value: sv as u64,
            });
        }
        let id = r.read_array::<32>("RegistryRecordV1.id")?;
        let proof_system_id = r.read_u16("RegistryRecordV1.proof_system_id")?;
        let audit_commitment = r.read_array::<32>("RegistryRecordV1.audit_commitment")?;
        let source_commitment = r.read_array::<32>("RegistryRecordV1.source_commitment")?;
        let ceremony_commitment = r.read_array::<32>("RegistryRecordV1.ceremony_commitment")?;
        let verifier_binary_version = r.read_u32("RegistryRecordV1.verifier_binary_version")?;
        let activation_height = r.read_u64("RegistryRecordV1.activation_height")?;
        let status =
            RegistryStatus::from_u8(r.read_u8("RegistryRecordV1.status")?, "RegistryRecordV1.status")?;
        let approval_threshold_bps = r.read_u16("RegistryRecordV1.approval_threshold_bps")?;
        let rec = Self {
            id,
            proof_system_id,
            audit_commitment,
            source_commitment,
            ceremony_commitment,
            verifier_binary_version,
            activation_height,
            status,
            approval_threshold_bps,
        };
        rec.validate()?;
        Ok(rec)
    }

    /// Decode from a complete buffer, rejecting any trailing bytes.
    pub fn decode_exact(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let v = Self::decode(&mut r)?;
        r.finish("RegistryRecordV1")?;
        Ok(v)
    }

    /// Content identity of the record = `BLAKE3(canonical encoding)`.
    pub fn identity(&self) -> [u8; 32] {
        blake3::hash(&self.encode()).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Independent re-derivation: recompute the id straight from `blake3::Hasher`
    // (a different code path than `prefixed`) and assert equality. Guards against
    // `prefixed` ever changing shape under the ids.
    fn independent(tag: &[u8], data: &[u8]) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(tag);
        h.update(data);
        *h.finalize().as_bytes()
    }

    #[test]
    fn tags_are_nul_terminated_and_exact() {
        assert_eq!(*VK_ID_TAG.last().unwrap(), 0u8);
        assert_eq!(*TOKENIZER_ID_TAG.last().unwrap(), 0u8);
        assert_eq!(*GRAPH_DEFINITION_TAG.last().unwrap(), 0u8);
        // Exact frozen bytes (the trailing NUL is part of the tag).
        assert_eq!(VK_ID_TAG, b"SUMCHAIN/REGISTRY/VK/v1\0");
        assert_eq!(TOKENIZER_ID_TAG, b"SUMCHAIN/REGISTRY/TOKENIZER/v1\0");
        assert_eq!(GRAPH_DEFINITION_TAG, b"SUMCHAIN/REGISTRY/GRAPHDEF/v1\0");
        // No interior NUL before the terminator (would signal a truncated tag).
        assert_eq!(VK_ID_TAG.iter().filter(|&&b| b == 0).count(), 1);
        assert_eq!(TOKENIZER_ID_TAG.iter().filter(|&&b| b == 0).count(), 1);
        assert_eq!(GRAPH_DEFINITION_TAG.iter().filter(|&&b| b == 0).count(), 1);
    }

    #[test]
    fn vk_id_matches_independent_derivation() {
        let manifest = [0x11u8; 32];
        let psid = 0x0007u16;
        let mut data = Vec::new();
        data.extend_from_slice(&manifest);
        data.extend_from_slice(&psid.to_le_bytes());
        assert_eq!(vk_id(&manifest, psid), independent(VK_ID_TAG, &data));
    }

    #[test]
    fn vk_id_binds_proof_system() {
        // Same VK material, different proof systems → different ids.
        let manifest = [0x22u8; 32];
        assert_ne!(vk_id(&manifest, 1), vk_id(&manifest, 2));
        // LE encoding: proof_system_id 0x0102 differs from 0x0201.
        assert_ne!(vk_id(&manifest, 0x0102), vk_id(&manifest, 0x0201));
    }

    #[test]
    fn tokenizer_id_matches_independent_derivation() {
        let bytes = b"example-tokenizer-canonical-bytes";
        assert_eq!(tokenizer_id(bytes), independent(TOKENIZER_ID_TAG, bytes));
    }

    #[test]
    fn graph_root_matches_independent_derivation() {
        let bytes = b"example-canonical-graph-encoding";
        assert_eq!(
            graph_definition_root(bytes),
            independent(GRAPH_DEFINITION_TAG, bytes)
        );
    }

    #[test]
    fn domain_separation_across_registry_family() {
        // The SAME input bytes under different family tags must yield different
        // ids (domain-confusion resistance). vk_id's input is 34 bytes; feed the
        // other two the identical 34 bytes so only the tag differs.
        let manifest = [0x33u8; 32];
        let psid = 0x0009u16;
        let mut data = Vec::new();
        data.extend_from_slice(&manifest);
        data.extend_from_slice(&psid.to_le_bytes());

        let a = vk_id(&manifest, psid);
        let b = tokenizer_id(&data);
        let c = graph_definition_root(&data);
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
    }

    // Frozen golden KATs — regression vectors (b3sum), NOT proofs. Captured on
    // first run; if these change, a domain tag or preimage layout moved.
    #[test]
    fn golden_vectors() {
        assert_eq!(
            hex::encode(vk_id(&[0xABu8; 32], 0x0001)),
            "5ed6cb60d5e3fcb43cc9373ba7a91d8bdc244533ec3fae81cf24cbd8657a4267",
        );
        assert_eq!(
            hex::encode(tokenizer_id(b"tokenizer/v1")),
            "fef596fab589d3a8d815f52408eac5a2a54b271241d1e776ce311ccffff6746e",
        );
    }

    // ---- RegistryRecordV1 ----

    fn sample_record() -> RegistryRecordV1 {
        RegistryRecordV1 {
            id: [0x01u8; 32],
            proof_system_id: 0x0007,
            audit_commitment: [0xA1u8; 32],
            source_commitment: [0xB2u8; 32],
            ceremony_commitment: [0xC3u8; 32],
            verifier_binary_version: 0x0000_002A,
            activation_height: 0, // governance value deferred; 0 while dormant
            status: RegistryStatus::Enabled,
            approval_threshold_bps: 0, // governance value deferred
        }
    }

    #[test]
    fn record_len_is_fixed_154() {
        assert_eq!(RegistryRecordV1::LEN, 154);
        assert_eq!(sample_record().try_encode().unwrap().len(), 154);
    }

    #[test]
    fn record_roundtrip() {
        let rec = sample_record();
        let bytes = rec.try_encode().unwrap();
        let back = RegistryRecordV1::decode_exact(&bytes).unwrap();
        assert_eq!(rec, back);
    }

    #[test]
    fn record_status_disabled_roundtrips() {
        let mut rec = sample_record();
        rec.status = RegistryStatus::Disabled;
        let bytes = rec.try_encode().unwrap();
        assert_eq!(RegistryRecordV1::decode_exact(&bytes).unwrap().status, RegistryStatus::Disabled);
    }

    #[test]
    fn record_rejects_bad_magic() {
        let mut bytes = sample_record().try_encode().unwrap();
        bytes[0] ^= 0xFF;
        assert!(matches!(
            RegistryRecordV1::decode_exact(&bytes),
            Err(DecodeError::BadTag { .. })
        ));
    }

    #[test]
    fn record_rejects_bad_schema_version() {
        let mut bytes = sample_record().try_encode().unwrap();
        // schema_version is the u16 right after the 7-byte magic.
        bytes[7] = 0x02;
        bytes[8] = 0x00;
        assert!(matches!(
            RegistryRecordV1::decode_exact(&bytes),
            Err(DecodeError::BadFixedScalar { .. })
        ));
    }

    #[test]
    fn record_rejects_bad_status() {
        let mut bytes = sample_record().try_encode().unwrap();
        // status is the single byte before the trailing u16 (offset LEN-3).
        let off = RegistryRecordV1::LEN - 3;
        bytes[off] = 0x07; // not 0/1
        assert!(matches!(
            RegistryRecordV1::decode_exact(&bytes),
            Err(DecodeError::BadValue { .. })
        ));
    }

    #[test]
    fn record_rejects_trailing_bytes() {
        let mut bytes = sample_record().try_encode().unwrap();
        bytes.push(0x00);
        assert!(matches!(
            RegistryRecordV1::decode_exact(&bytes),
            Err(DecodeError::TrailingBytes { remaining: 1, .. })
        ));
    }

    #[test]
    fn record_rejects_truncation() {
        let bytes = sample_record().try_encode().unwrap();
        assert!(matches!(
            RegistryRecordV1::decode_exact(&bytes[..bytes.len() - 1]),
            Err(DecodeError::Truncated { .. })
        ));
    }

    #[test]
    fn record_domain_confusion_rejected() {
        // A RegistryRecordV1 decoder must reject another struct's bytes: the
        // registry KDF outputs are 32 bytes with no RREG magic → BadTag/Truncated.
        let not_a_record = vk_id(&[0u8; 32], 0);
        assert!(RegistryRecordV1::decode_exact(&not_a_record).is_err());
    }

    #[test]
    fn record_encoding_matches_independent_construction() {
        // Independent decoding check: rebuild the expected bytes field-by-field
        // (a separate code path from `encode`) and assert equality + exact offsets.
        let rec = sample_record();
        let got = rec.try_encode().unwrap();

        let mut want = Vec::new();
        want.extend_from_slice(b"RREGv1\0"); // 7
        want.extend_from_slice(&1u16.to_le_bytes()); // schema_version
        want.extend_from_slice(&[0x01u8; 32]); // id
        want.extend_from_slice(&0x0007u16.to_le_bytes()); // proof_system_id
        want.extend_from_slice(&[0xA1u8; 32]); // audit
        want.extend_from_slice(&[0xB2u8; 32]); // source
        want.extend_from_slice(&[0xC3u8; 32]); // ceremony
        want.extend_from_slice(&0x0000_002Au32.to_le_bytes()); // verifier_binary_version
        want.extend_from_slice(&0u64.to_le_bytes()); // activation_height
        want.push(0u8); // status = Enabled
        want.extend_from_slice(&0u16.to_le_bytes()); // approval_threshold_bps

        assert_eq!(want.len(), RegistryRecordV1::LEN);
        assert_eq!(got, want);
    }

    #[test]
    fn record_identity_golden() {
        // Frozen regression vector (b3sum of the canonical encoding) for the
        // sample record — a KAT, not a proof.
        assert_eq!(
            hex::encode(sample_record().identity()),
            "41e630d665bbccba04aed4bec75f8a289d922250c34b7cd66679131b26ab3ac0",
        );
    }
}
