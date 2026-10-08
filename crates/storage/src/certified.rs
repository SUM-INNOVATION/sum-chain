//! Certified commit: a DORMANT, library-independent storage seam for #270.
//!
//! Nothing in the node, consensus or RPC crates calls this module, and
//! `tests/certified_commit_dormant.rs` fails if anything outside this crate
//! starts to. Production publication is unchanged: it still goes through
//! [`AcceptedCandidate::publish`], and the legacy local-depth pointer
//! (`meta_keys::FINALIZED_HEIGHT` / `FINALIZED_HASH`) is neither read nor
//! written here.
//!
//! # What is deliberately NOT decided here
//!
//! * **No bytes are frozen.** A certificate is opaque bytes checked by an
//!   injected [`CertificateVerifier`]; where the certificate and the finalized
//!   pointer live, and how the pointer is encoded, come from an injected
//!   [`CertifiedLayout`]. Neither trait has a production implementation. The
//!   tests use a test-only certificate and a test-only layout, which are not a
//!   proposal for either encoding.
//! * **No commit rule is ratified.** The seam implements the storage half of
//!   commit-on-certificate (decision F-1, proposed, not ratified): a block
//!   becomes canonical only together with its certificate. If F-1 is not
//!   adopted this module is deleted, not adapted.
//! * **No consensus library is chosen.** Nothing here knows about rounds,
//!   votes or proposers; whatever engine produces a decision hands this seam an
//!   accepted candidate and certificate bytes.
//!
//! # Safety requirements (library-independent, each tested)
//!
//! | id  | requirement | test(s) in `tests/certified_commit.rs` |
//! |-----|-------------|-----------------------------------------|
//! | S1  | A block becomes certified-final only with a certificate the verifier accepts for exactly that (height, block hash). | `s1_*` |
//! | S2  | State writes, block, publication indexes, certificate and finalized pointer are written in ONE batch, committed with a synced WAL; after any crash either all are present or none is. | `s2_*` |
//! | S3  | The finalized pointer never decreases and advances by exactly one height, to a block whose parent is the previous pointer. | `s3_*` |
//! | S4  | No unwind (rollback or reorg) may remove or replace a block at or below the finalized pointer. | `s4_*` |
//! | S5  | A valid certificate for a height at or below the pointer that names a different block is refused as conflicting; it is never applied. | `s5_*` |
//! | S6  | Restart recovers exactly the committed pointer, re-verifies its certificate and block, and refuses (never resets) on missing or corrupt finality data. | `s6_*` |
//! | S7  | Certified execution requires the exact state root: a legacy-window force-adoption can never be certified. | `s7_*` |
//! | S8  | Once a pointer exists, no canonical block exists above it (no uncertified canonical head). | `s8_*` |
//!
//! These are storage obligations only. Vote signing, locking and the safety
//! WAL (decision F-3) are outside this module.
//!
//! [`AcceptedCandidate::publish`]: crate::candidate::AcceptedCandidate::publish

use std::fmt;

use sumchain_primitives::{Block, BlockHeight, Hash};

use crate::candidate::{Acceptance, AcceptedCandidate};
use crate::db::{cf, Database};
use crate::schema::meta_keys;
use crate::StorageError;

/// The finalized pointer: the highest block committed with a certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalizedPointer {
    pub height: BlockHeight,
    pub hash: Hash,
}

/// Why a verifier refused a certificate. Free text: the verifier owns the
/// encoding, so this seam cannot classify its reasons.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateRefusal(pub String);

impl fmt::Display for CertificateRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Checks that opaque certificate bytes prove a quorum decision for exactly
/// `(height, block_hash)`.
///
/// The seam passes the height and hash of the block it is about to commit, so
/// a certificate for any other block must be refused by the verifier. The seam
/// does not parse the bytes and assumes nothing about their layout, the
/// signature scheme or how the validator set is resolved.
pub trait CertificateVerifier {
    fn verify(
        &self,
        height: BlockHeight,
        block_hash: &Hash,
        certificate: &[u8],
    ) -> std::result::Result<(), CertificateRefusal>;
}

/// Where certified records live and how the pointer is encoded.
///
/// Injected so that no key or byte layout is frozen by this seam. Every column
/// family named must already exist; the seam adds none.
pub trait CertifiedLayout {
    /// Column family and key of the certificate for `(height, block_hash)`.
    fn certificate_key(&self, height: BlockHeight, block_hash: &Hash) -> (&'static str, Vec<u8>);
    /// Column family and key of the finalized pointer.
    fn pointer_key(&self) -> (&'static str, Vec<u8>);
    fn encode_pointer(&self, pointer: &FinalizedPointer) -> Vec<u8>;
    /// Must refuse anything it did not produce; the seam never falls back.
    fn decode_pointer(&self, bytes: &[u8]) -> std::result::Result<FinalizedPointer, String>;
}

/// Every way the seam refuses. None of them writes anything.
#[derive(Debug)]
pub enum CertifiedError {
    Storage(StorageError),
    /// S1: the verifier refused the certificate for this block.
    CertificateRefused {
        height: BlockHeight,
        block_hash: Hash,
        reason: CertificateRefusal,
    },
    /// S7: only an exact-root (or self-produced) execution can be certified.
    NotExactRoot {
        height: BlockHeight,
        acceptance: Acceptance,
    },
    /// S3: the block does not extend the finalized pointer by one height.
    DoesNotExtendFinalized {
        height: BlockHeight,
        parent: Hash,
        finalized: FinalizedPointer,
    },
    /// No pointer yet and the block does not extend the canonical head.
    DoesNotExtendHead {
        height: BlockHeight,
        parent: Hash,
        head: Option<(BlockHeight, Hash)>,
    },
    /// The block is already certified-final: nothing to do, nothing written.
    AlreadyFinal {
        height: BlockHeight,
        block_hash: Hash,
    },
    /// S5: a valid certificate for a different block at a final height.
    ConflictingCertificate {
        height: BlockHeight,
        final_hash: Hash,
        presented_hash: Hash,
    },
    /// S4: an unwind would cross the finalized pointer.
    UnwindAcrossFinality {
        target_height: BlockHeight,
        finalized: FinalizedPointer,
    },
    /// S8: a canonical block exists above the finalized pointer.
    UncertifiedCanonicalHead {
        head: (BlockHeight, Hash),
        finalized: FinalizedPointer,
    },
    /// S6: finality data is missing or does not verify. Never reset.
    Corrupt(String),
    /// Test-only fault injection aborted the commit (see `commit_observed`).
    Injected(CommitStep),
}

impl fmt::Display for CertifiedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(e) => write!(f, "storage: {e}"),
            Self::CertificateRefused {
                height,
                block_hash,
                reason,
            } => {
                write!(
                    f,
                    "certificate for block {block_hash} at height {height} refused: {reason}"
                )
            }
            Self::NotExactRoot { height, acceptance } => write!(
                f,
                "block at height {height} was accepted as {acceptance:?}; only an exact-root \
                 execution can be certified"
            ),
            Self::DoesNotExtendFinalized {
                height,
                parent,
                finalized,
            } => write!(
                f,
                "block at height {height} with parent {parent} does not extend the finalized \
                 pointer {} at height {}",
                finalized.hash, finalized.height
            ),
            Self::DoesNotExtendHead {
                height,
                parent,
                head,
            } => write!(
                f,
                "first certified block at height {height} with parent {parent} does not extend \
                 the canonical head {head:?}"
            ),
            Self::AlreadyFinal { height, block_hash } => {
                write!(f, "block {block_hash} at height {height} is already final")
            }
            Self::ConflictingCertificate {
                height,
                final_hash,
                presented_hash,
            } => write!(
                f,
                "conflicting certificate at final height {height}: final block {final_hash}, \
                 certificate names {presented_hash}"
            ),
            Self::UnwindAcrossFinality {
                target_height,
                finalized,
            } => write!(
                f,
                "refusing to unwind to height {target_height}: blocks up to {} are final",
                finalized.height
            ),
            Self::UncertifiedCanonicalHead { head, finalized } => write!(
                f,
                "canonical head {} at height {} is above the finalized pointer at height {}",
                head.1, head.0, finalized.height
            ),
            Self::Corrupt(why) => write!(f, "finality data unusable: {why}"),
            Self::Injected(step) => write!(f, "fault injected at {step:?}"),
        }
    }
}

impl std::error::Error for CertifiedError {}

impl From<StorageError> for CertifiedError {
    fn from(e: StorageError) -> Self {
        Self::Storage(e)
    }
}

pub type Result<T> = std::result::Result<T, CertifiedError>;

/// Points inside [`CertifiedStore::commit`] at which a test can abort.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitStep {
    /// State rows, block and publication indexes staged in the overlay.
    CanonicalSetStaged,
    /// Certificate row staged.
    CertificateStaged,
    /// Finalized pointer staged.
    PointerStaged,
    /// Overlay converted to a batch; nothing written yet.
    BatchBuilt,
    /// The synced batch has been committed.
    Committed,
}

/// The result of checking a certificate a peer presented (importer path).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateCheck {
    /// Valid, and names the block already final at that height.
    AlreadyFinal,
    /// Valid, for the next height above the pointer (or above the head when
    /// no pointer exists yet). The block still has to be executed and
    /// committed through [`CertifiedStore::commit`].
    NextHeight,
    /// Valid, for a height more than one above the pointer. Not committable
    /// until the gap is filled.
    Ahead,
    /// Valid, but no certified commit has happened yet and the height is at or
    /// below the canonical head: pre-activation history, which this seam does
    /// not judge (its trust boundary is the bootstrap checkpoint, not ours).
    BelowCertifiedRange,
}

/// What restart recovery found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recovery {
    /// No certified commit has ever happened on this database.
    NeverCertified,
    /// The pointer, its block and its certificate all verify, and the
    /// canonical head is the pointer.
    Finalized(FinalizedPointer),
}

/// The dormant seam. Holds a database, a layout and a verifier; owns no
/// in-memory finality state, so every answer is read back from storage.
pub struct CertifiedStore<'db, L, V> {
    db: &'db Database,
    layout: L,
    verifier: V,
}

impl<'db, L: CertifiedLayout, V: CertificateVerifier> CertifiedStore<'db, L, V> {
    pub fn new(db: &'db Database, layout: L, verifier: V) -> Self {
        Self {
            db,
            layout,
            verifier,
        }
    }

    /// The committed finalized pointer, if any. A pointer that does not
    /// decode is an error, never `None` (S6).
    pub fn finalized(&self) -> Result<Option<FinalizedPointer>> {
        let (cf_name, key) = self.layout.pointer_key();
        match self.db.get(cf_name, &key)? {
            None => Ok(None),
            Some(bytes) => self
                .layout
                .decode_pointer(&bytes)
                .map(Some)
                .map_err(|e| CertifiedError::Corrupt(format!("finalized pointer: {e}"))),
        }
    }

    /// The stored certificate for `(height, block_hash)`, if any.
    pub fn certificate(&self, height: BlockHeight, block_hash: &Hash) -> Result<Option<Vec<u8>>> {
        let (cf_name, key) = self.layout.certificate_key(height, block_hash);
        Ok(self.db.get(cf_name, &key)?)
    }

    fn verify(&self, height: BlockHeight, block_hash: &Hash, certificate: &[u8]) -> Result<()> {
        self.verifier
            .verify(height, block_hash, certificate)
            .map_err(|reason| CertifiedError::CertificateRefused {
                height,
                block_hash: *block_hash,
                reason,
            })
    }

    fn canonical_head(&self) -> Result<Option<(BlockHeight, Hash)>> {
        let hash = self.db.get(cf::META, meta_keys::LATEST_BLOCK_HASH)?;
        let height = self.db.get(cf::META, meta_keys::LATEST_BLOCK_HEIGHT)?;
        match (hash, height) {
            (None, None) => Ok(None),
            (Some(hash), Some(height)) => {
                let hash = Hash::from_slice(&hash)
                    .map_err(|e| CertifiedError::Corrupt(format!("head hash: {e}")))?;
                let height: [u8; 8] = height
                    .as_slice()
                    .try_into()
                    .map_err(|_| CertifiedError::Corrupt("head height is not 8 bytes".into()))?;
                Ok(Some((u64::from_be_bytes(height), hash)))
            }
            _ => Err(CertifiedError::Corrupt(
                "head hash and height disagree on presence".into(),
            )),
        }
    }

    fn canonical_hash_at(&self, height: BlockHeight) -> Result<Option<Hash>> {
        match self.db.get(cf::BLOCK_HEIGHT, &height.to_be_bytes())? {
            None => Ok(None),
            Some(bytes) => Hash::from_slice(&bytes)
                .map(Some)
                .map_err(|e| CertifiedError::Corrupt(format!("height index {height}: {e}"))),
        }
    }

    /// The pointer, after checking that nothing canonical sits above it (S8).
    fn checked_pointer(&self) -> Result<Option<FinalizedPointer>> {
        let pointer = self.finalized()?;
        if let Some(p) = pointer {
            match self.canonical_head()? {
                Some(head) if head == (p.height, p.hash) => {}
                Some(head) => {
                    return Err(CertifiedError::UncertifiedCanonicalHead { head, finalized: p })
                }
                None => {
                    return Err(CertifiedError::Corrupt(
                        "a finalized pointer exists but there is no canonical head".into(),
                    ))
                }
            }
        }
        Ok(pointer)
    }

    /// Commit an accepted candidate together with its certificate.
    ///
    /// Refuses, writing nothing, unless: the candidate's root was checked
    /// exactly (S7); the block extends the finalized pointer by one height, or
    /// the canonical head when no pointer exists yet (S3); and the verifier
    /// accepts the certificate for exactly this block (S1). Then writes the
    /// canonical set, the certificate and the new pointer in one synced batch
    /// (S2).
    pub fn commit(
        &self,
        candidate: AcceptedCandidate<'db, '_>,
        certificate: &[u8],
    ) -> Result<FinalizedPointer> {
        self.commit_observed(candidate, certificate, &mut |_| Ok(()))
    }

    /// [`Self::commit`] with an observer called at each [`CommitStep`]. An
    /// observer error aborts the commit at that point. Exists so tests can
    /// abort (or kill the process) between steps; production has no caller.
    pub fn commit_observed(
        &self,
        candidate: AcceptedCandidate<'db, '_>,
        certificate: &[u8],
        observe: &mut dyn FnMut(CommitStep) -> Result<()>,
    ) -> Result<FinalizedPointer> {
        let height = candidate.height();
        let block_hash = candidate.block_hash();

        match candidate.acceptance() {
            Acceptance::ExactRoot | Acceptance::Produced => {}
            other => {
                return Err(CertifiedError::NotExactRoot {
                    height,
                    acceptance: other.clone(),
                })
            }
        }

        // Verify before classifying the position, so an invalid certificate
        // is reported as invalid and never as a conflict.
        self.verify(height, &block_hash, certificate)?;
        let pointer = self.checked_pointer()?;
        self.check_position(pointer, height, block_hash, candidate.parent_hash())?;
        let (mut overlay, block, _acceptance) = candidate.into_staged_overlay()?;
        debug_assert_eq!(block.hash(), block_hash);
        observe(CommitStep::CanonicalSetStaged)?;

        let (cert_cf, cert_key) = self.layout.certificate_key(height, &block_hash);
        overlay.put(cert_cf, &cert_key, certificate)?;
        observe(CommitStep::CertificateStaged)?;

        let pointer = FinalizedPointer {
            height,
            hash: block_hash,
        };
        let (ptr_cf, ptr_key) = self.layout.pointer_key();
        overlay.put(ptr_cf, &ptr_key, &self.layout.encode_pointer(&pointer))?;
        observe(CommitStep::PointerStaged)?;

        let batch = overlay.into_batch()?;
        observe(CommitStep::BatchBuilt)?;

        batch.commit_durable()?;
        observe(CommitStep::Committed)?;
        Ok(pointer)
    }

    fn check_position(
        &self,
        pointer: Option<FinalizedPointer>,
        height: BlockHeight,
        block_hash: Hash,
        parent: Hash,
    ) -> Result<()> {
        match pointer {
            Some(p) if height <= p.height => match self.canonical_hash_at(height)? {
                Some(h) if h == block_hash => {
                    Err(CertifiedError::AlreadyFinal { height, block_hash })
                }
                Some(h) => Err(CertifiedError::ConflictingCertificate {
                    height,
                    final_hash: h,
                    presented_hash: block_hash,
                }),
                None => Err(CertifiedError::Corrupt(format!(
                    "no canonical block at final height {height}"
                ))),
            },
            Some(p) => {
                if height == p.height + 1 && parent == p.hash {
                    Ok(())
                } else {
                    Err(CertifiedError::DoesNotExtendFinalized {
                        height,
                        parent,
                        finalized: p,
                    })
                }
            }
            None => {
                let head = self.canonical_head()?;
                match head {
                    Some((h, hash)) if height == h + 1 && parent == hash => Ok(()),
                    _ => Err(CertifiedError::DoesNotExtendHead {
                        height,
                        parent,
                        head,
                    }),
                }
            }
        }
    }

    /// Importer check for a certificate a peer presented (S1, S5). Verifies
    /// first, so an invalid certificate is never reported as a conflict.
    pub fn check_certificate(
        &self,
        height: BlockHeight,
        block_hash: &Hash,
        certificate: &[u8],
    ) -> Result<CertificateCheck> {
        self.verify(height, block_hash, certificate)?;
        let base = match self.checked_pointer()? {
            Some(p) => {
                if height <= p.height {
                    // Every height up to the pointer is final: the pointer's
                    // certificate fixes its whole ancestry.
                    return match self.canonical_hash_at(height)? {
                        Some(h) if h == *block_hash => Ok(CertificateCheck::AlreadyFinal),
                        Some(h) => Err(CertifiedError::ConflictingCertificate {
                            height,
                            final_hash: h,
                            presented_hash: *block_hash,
                        }),
                        None => Err(CertifiedError::Corrupt(format!(
                            "no canonical block at final height {height}"
                        ))),
                    };
                }
                p.height
            }
            None => match self.canonical_head()? {
                Some((h, _)) if height <= h => return Ok(CertificateCheck::BelowCertifiedRange),
                Some((h, _)) => h,
                None => return Ok(CertificateCheck::Ahead),
            },
        };
        if height == base + 1 {
            Ok(CertificateCheck::NextHeight)
        } else {
            Ok(CertificateCheck::Ahead)
        }
    }

    /// Guard for any unwind (rollback or reorg) that would reset the head to
    /// `target_height` (S4). Unwinding to exactly the pointer is allowed only
    /// in the sense that nothing above it exists to unwind (S8).
    pub fn check_unwind_target(&self, target_height: BlockHeight) -> Result<()> {
        match self.finalized()? {
            Some(p) if target_height < p.height => Err(CertifiedError::UnwindAcrossFinality {
                target_height,
                finalized: p,
            }),
            _ => Ok(()),
        }
    }

    /// Guard for a set of blocks an unwind would abandon (S4).
    pub fn check_abandoned(&self, abandoned: &[Block]) -> Result<()> {
        if let Some(p) = self.finalized()? {
            if let Some(lowest) = abandoned.iter().map(Block::height).min() {
                if lowest <= p.height {
                    return Err(CertifiedError::UnwindAcrossFinality {
                        target_height: lowest.saturating_sub(1),
                        finalized: p,
                    });
                }
            }
        }
        Ok(())
    }

    /// Restart recovery (S6, S8): read the pointer and re-establish that its
    /// block is canonical, decodes to the same hash, carries a certificate
    /// that still verifies, and is the canonical head. Any failure is an
    /// error; nothing is reset or rewritten.
    pub fn recover(&self) -> Result<Recovery> {
        let Some(p) = self.checked_pointer()? else {
            return Ok(Recovery::NeverCertified);
        };
        match self.canonical_hash_at(p.height)? {
            Some(h) if h == p.hash => {}
            other => {
                return Err(CertifiedError::Corrupt(format!(
                    "height index at {} is {other:?}, pointer says {}",
                    p.height, p.hash
                )))
            }
        }
        let block_bytes = self.db.get(cf::BLOCKS, p.hash.as_bytes())?.ok_or_else(|| {
            CertifiedError::Corrupt(format!("finalized block {} missing", p.hash))
        })?;
        let block = Block::from_bytes(&block_bytes)
            .map_err(|e| CertifiedError::Corrupt(format!("finalized block undecodable: {e}")))?;
        if block.hash() != p.hash || block.height() != p.height {
            return Err(CertifiedError::Corrupt(
                "finalized block does not match the pointer".into(),
            ));
        }
        let certificate = self.certificate(p.height, &p.hash)?.ok_or_else(|| {
            CertifiedError::Corrupt(format!("certificate for {} missing", p.hash))
        })?;
        self.verify(p.height, &p.hash, &certificate)
            .map_err(|e| CertifiedError::Corrupt(format!("stored certificate: {e}")))?;
        Ok(Recovery::Finalized(p))
    }
}

impl From<CommitStep> for CertifiedError {
    fn from(step: CommitStep) -> Self {
        Self::Injected(step)
    }
}
