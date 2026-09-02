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
}
