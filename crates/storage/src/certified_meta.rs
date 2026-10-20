//! Storage layout v1 for the DORMANT certified-commit seam ([`crate::certified`]):
//! versioned keys in the EXISTING `meta` column family.
//!
//! Nothing outside `sumchain-storage` uses this module (the seam's dormancy
//! test still holds), and nothing in this crate calls it from a production
//! path. It changes no running node.
//!
//! # Keys and values (all in `cf::META`; no new column family)
//!
//! | Record | Key | Value |
//! |---|---|---|
//! | certificate | [`CERTIFICATE_KEY_PREFIX`] `finality/cert/v1/` ‖ height u64 **BE** ‖ block hash (32), 57 bytes | the `FinalityCertificateV1` bytes, opaque here |
//! | finalized pointer | [`FINALIZED_POINTER_KEY`] `finality/finalized/v1` | height u64 **LE** ‖ block hash (32), 40 bytes |
//!
//! Integers are big-endian only in keys, so certificate keys sort by height,
//! and little-endian in values (A1, D0). The legacy local-depth records
//! `finalized_height` / `finalized_hash` are neither read nor written.
//!
//! # Why `meta` and not a new column family
//!
//! A binary that does not name a column family cannot open a volume on which
//! a newer binary created that family. The deployed 0.2.0-era binary treats
//! the resulting open error as corruption and auto-repairs the volume to empty
//! (see `Database::repair`). Keys in an existing family carry no such hazard:
//! an older binary opens the volume and never reads them.
//!
//! # Writes
//!
//! Through the seam only: [`crate::certified::CertifiedStore::commit`] stages
//! the canonical set, the certificate row and the pointer in one overlay and
//! commits them as one synced batch.
//!
//! # Reads are fail-closed
//!
//! [`recover_v1`] runs the seam's recovery (pointer, canonical block, stored
//! certificate re-verified by the injected verifier) and then
//! [`audit_namespace`]: every key under the certificate prefix must parse
//! exactly, sit at or below the pointer on the canonical chain, and verify for
//! the (height, hash) its key names; a certificate without a pointer, or a
//! pointer without its certificate, is refused. Nothing is ever repaired,
//! rewritten or deleted here.

use std::fmt;

use sumchain_primitives::{BlockHeight, Hash};

use crate::certified::{
    CertificateRefusal, CertificateVerifier, CertifiedError, CertifiedLayout, CertifiedStore,
    FinalizedPointer, Recovery,
};
use crate::db::{cf, Database};
use crate::StorageError;

/// Prefix of every certificate key in `cf::META`.
pub const CERTIFICATE_KEY_PREFIX: &[u8] = b"finality/cert/v1/";
/// The finalized pointer's key in `cf::META`.
pub const FINALIZED_POINTER_KEY: &[u8] = b"finality/finalized/v1";
/// Length of a certificate key: prefix ‖ height u64 ‖ block hash.
pub const CERTIFICATE_KEY_LEN: usize = CERTIFICATE_KEY_PREFIX.len() + 8 + 32;
/// Length of the pointer value: height u64 LE ‖ block hash.
pub const FINALIZED_POINTER_LEN: usize = 8 + 32;

/// The certificate key for `(height, block_hash)`.
pub fn certificate_key(height: BlockHeight, block_hash: &Hash) -> Vec<u8> {
    let mut key = Vec::with_capacity(CERTIFICATE_KEY_LEN);
    key.extend_from_slice(CERTIFICATE_KEY_PREFIX);
    key.extend_from_slice(&height.to_be_bytes());
    key.extend_from_slice(block_hash.as_bytes());
    key
}

/// Strict parse of a certificate key: the exact prefix and exactly 40 more
/// bytes. Anything else is `None`.
pub fn parse_certificate_key(key: &[u8]) -> Option<(BlockHeight, Hash)> {
    if key.len() != CERTIFICATE_KEY_LEN || !key.starts_with(CERTIFICATE_KEY_PREFIX) {
        return None;
    }
    let rest = &key[CERTIFICATE_KEY_PREFIX.len()..];
    let height = u64::from_be_bytes(rest[..8].try_into().expect("8 bytes"));
    let hash = Hash::from_slice(&rest[8..]).ok()?;
    Some((height, hash))
}

/// The 40-byte pointer value.
pub fn encode_pointer(pointer: &FinalizedPointer) -> [u8; FINALIZED_POINTER_LEN] {
    let mut out = [0u8; FINALIZED_POINTER_LEN];
    out[..8].copy_from_slice(&pointer.height.to_le_bytes());
    out[8..].copy_from_slice(pointer.hash.as_bytes());
    out
}

/// Strict decode of the pointer value: exactly 40 bytes.
pub fn decode_pointer(bytes: &[u8]) -> Result<FinalizedPointer, String> {
    if bytes.len() != FINALIZED_POINTER_LEN {
        return Err(format!(
            "pointer is {} bytes, not {FINALIZED_POINTER_LEN}",
            bytes.len()
        ));
    }
    let height = u64::from_le_bytes(bytes[..8].try_into().expect("8 bytes"));
    let hash = Hash::from_slice(&bytes[8..]).map_err(|e| format!("pointer hash: {e}"))?;
    Ok(FinalizedPointer { height, hash })
}

/// The v1 layout for [`CertifiedStore`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MetaLayoutV1;

impl CertifiedLayout for MetaLayoutV1 {
    fn certificate_key(&self, height: BlockHeight, block_hash: &Hash) -> (&'static str, Vec<u8>) {
        (cf::META, certificate_key(height, block_hash))
    }
    fn pointer_key(&self) -> (&'static str, Vec<u8>) {
        (cf::META, FINALIZED_POINTER_KEY.to_vec())
    }
    fn encode_pointer(&self, pointer: &FinalizedPointer) -> Vec<u8> {
        encode_pointer(pointer).to_vec()
    }
    fn decode_pointer(&self, bytes: &[u8]) -> Result<FinalizedPointer, String> {
        decode_pointer(bytes)
    }
}

/// A rule of the v1 namespace a stored record breaks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NamespaceViolation {
    /// The pointer value is not exactly 40 well-formed bytes.
    UndecodablePointer(String),
    /// A key under the certificate prefix does not parse exactly.
    MalformedCertificateKey(Vec<u8>),
    /// A certificate exists, but no pointer does.
    CertificateWithoutPointer { height: BlockHeight, hash: Hash },
    /// A certificate sits above the pointer.
    CertificateAbovePointer {
        height: BlockHeight,
        hash: Hash,
        finalized: FinalizedPointer,
    },
    /// A certificate names a block that is not canonical at its height.
    CertificateNotCanonical { height: BlockHeight, hash: Hash },
    /// A certificate does not verify for the (height, hash) its key names.
    CertificateRefused {
        height: BlockHeight,
        hash: Hash,
        reason: CertificateRefusal,
    },
    /// The pointer exists, but its block has no certificate.
    PointerWithoutCertificate(FinalizedPointer),
}

/// Why a namespace audit refused.
#[derive(Debug)]
pub enum NamespaceError {
    Storage(StorageError),
    Violation(NamespaceViolation),
}

impl fmt::Display for NamespaceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(e) => write!(f, "storage: {e}"),
            Self::Violation(v) => write!(f, "certified namespace v1: {v:?}"),
        }
    }
}

impl std::error::Error for NamespaceError {}

impl From<StorageError> for NamespaceError {
    fn from(e: StorageError) -> Self {
        Self::Storage(e)
    }
}

/// What an audit found when every rule held.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NamespaceAudit {
    pub pointer: Option<FinalizedPointer>,
    pub certificates: u64,
}

fn violation<T>(v: NamespaceViolation) -> Result<T, NamespaceError> {
    Err(NamespaceError::Violation(v))
}

fn canonical_hash_at(db: &Database, height: BlockHeight) -> Result<Option<Hash>, NamespaceError> {
    match db.get(cf::BLOCK_HEIGHT, &height.to_be_bytes())? {
        None => Ok(None),
        Some(bytes) => Ok(Hash::from_slice(&bytes).ok()),
    }
}

/// Check every v1 record against the namespace rules. Read-only.
///
/// Verifies every stored certificate with `verifier`, so its cost is one
/// verification per certified height: an explicit audit, not a per-open check.
pub fn audit_namespace(
    db: &Database,
    verifier: &dyn CertificateVerifier,
) -> Result<NamespaceAudit, NamespaceError> {
    let pointer = match db.get(cf::META, FINALIZED_POINTER_KEY)? {
        None => None,
        Some(bytes) => match decode_pointer(&bytes) {
            Ok(p) => Some(p),
            Err(e) => return violation(NamespaceViolation::UndecodablePointer(e)),
        },
    };
    let mut certificates = 0u64;
    let mut pointer_certified = false;
    for entry in db.prefix_iter_checked(cf::META, CERTIFICATE_KEY_PREFIX)? {
        let (key, value) = entry?;
        if !key.starts_with(CERTIFICATE_KEY_PREFIX) {
            break;
        }
        let Some((height, hash)) = parse_certificate_key(&key) else {
            return violation(NamespaceViolation::MalformedCertificateKey(key.to_vec()));
        };
        let Some(p) = pointer else {
            return violation(NamespaceViolation::CertificateWithoutPointer { height, hash });
        };
        if height > p.height {
            return violation(NamespaceViolation::CertificateAbovePointer {
                height,
                hash,
                finalized: p,
            });
        }
        if canonical_hash_at(db, height)? != Some(hash) {
            return violation(NamespaceViolation::CertificateNotCanonical { height, hash });
        }
        if let Err(reason) = verifier.verify(height, &hash, &value) {
            return violation(NamespaceViolation::CertificateRefused {
                height,
                hash,
                reason,
            });
        }
        if (height, hash) == (p.height, p.hash) {
            pointer_certified = true;
        }
        certificates += 1;
    }
    if let Some(p) = pointer {
        if !pointer_certified {
            return violation(NamespaceViolation::PointerWithoutCertificate(p));
        }
    }
    Ok(NamespaceAudit {
        pointer,
        certificates,
    })
}

/// Why [`recover_v1`] refused.
#[derive(Debug)]
pub enum RecoverV1Error {
    /// The seam's own recovery refused (S6, S8).
    Seam(CertifiedError),
    /// The seam's recovery passed, but the namespace audit did not.
    Namespace(NamespaceError),
}

impl fmt::Display for RecoverV1Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Seam(e) => write!(f, "{e}"),
            Self::Namespace(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for RecoverV1Error {}

struct ByRef<'a>(&'a dyn CertificateVerifier);

impl CertificateVerifier for ByRef<'_> {
    fn verify(
        &self,
        height: BlockHeight,
        block_hash: &Hash,
        certificate: &[u8],
    ) -> Result<(), CertificateRefusal> {
        self.0.verify(height, block_hash, certificate)
    }
}

/// Restart recovery for the v1 layout: the seam's [`CertifiedStore::recover`]
/// (pointer, canonical block, the pointer's certificate re-verified), then
/// [`audit_namespace`]. Refuses on any failure; writes nothing.
pub fn recover_v1(
    db: &Database,
    verifier: &dyn CertificateVerifier,
) -> Result<Recovery, RecoverV1Error> {
    let recovery = CertifiedStore::new(db, MetaLayoutV1, ByRef(verifier))
        .recover()
        .map_err(RecoverV1Error::Seam)?;
    audit_namespace(db, verifier).map_err(RecoverV1Error::Namespace)?;
    Ok(recovery)
}
