//! The identity envelope around the compute-pool and beacon undo journals.
//!
//! Issue #253. Both journals are addressed by `(height, block hash)`
//! ([`crate::schema::journal_key`]), so two competing blocks at one height no
//! longer share a row. Addressing is only half of it: a row KEY is a claim made
//! by whoever wrote the row, and nothing about a payload that decodes cleanly
//! proves it describes the block it was filed under — a producer bug, a row
//! copied between databases, or one family's record under the other family's
//! column. Replaying such a record restores a predecessor that never existed,
//! and every mutation in it looks plausible.
//!
//! So the record names its own block. The publisher, the one place where the
//! block hash is final, seals each payload with the family, height and hash it
//! belongs to; every reader opens it against the block it was asked to revert
//! and refuses any disagreement. There is no reconciliation: when the key and
//! the record disagree there is no way to know which one is right.
//!
//! # Wire format (version 1)
//!
//! ```text
//! offset  size  field
//!      0     4  magic            b"SJR1"
//!      4     1  version          1
//!      5     1  family           1 = compute pool, 2 = beacon
//!      6     8  height           u64, big-endian
//!     14    32  block hash
//!     46     4  payload length   u32, big-endian
//!     50     n  payload          the subsystem's own diff encoding
//! ```
//!
//! Exactly `50 + n` bytes: a short record and a record with trailing bytes are
//! both refused. Fixed-width big-endian fields make the layout independent of
//! the host, which the byte vectors in the tests pin on every CI architecture.
//!
//! # Presence is decided by the gate
//!
//! A block with the subsystem's gate open always publishes a record, an empty
//! payload when it changed nothing; a block with the gate closed never does.
//! Without the first half, "this block changed nothing" and "this block's undo
//! record is missing" are the same zero bytes on disk, and a revert that meets
//! the second silently leaves the abandoned block's rows applied. [`Expectation`]
//! turns the gate into the rule every reader enforces.
//!
//! # Compatibility
//!
//! Both gates are `None` on every deployed chain, and genesis validation refuses
//! a genesis that sets either, so no compute-pool or beacon journal row has ever
//! been written outside tests. A database created while both are dormant holds
//! none, which is exactly what [`Expectation::Absent`] requires, and the account
//! and contract journals are untouched. There is no earlier format to migrate:
//! an unsealed row is refused like any other corruption.

use sumchain_primitives::{BlockHeight, Hash};

/// First four bytes of every sealed record.
pub const MAGIC: [u8; 4] = *b"SJR1";

/// The only envelope version this binary writes or reads.
pub const VERSION: u8 = 1;

/// Bytes before the payload.
pub const HEADER_LEN: usize = 4 + 1 + 1 + 8 + 32 + 4;

/// The subsystem a record belongs to. Carried in the record so that one
/// family's journal filed under the other family's column is refused rather
/// than decoded by whichever codec happens to accept it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    ComputePool,
    Beacon,
}

impl Family {
    fn tag(self) -> u8 {
        match self {
            Family::ComputePool => 1,
            Family::Beacon => 2,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Family::ComputePool => "compute-pool",
            Family::Beacon => "beacon",
        }
    }
}

impl std::fmt::Display for Family {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Why a record was refused. Every variant is a halt for the revert that met it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EnvelopeError {
    #[error("{family} journal is {len} bytes, shorter than the {HEADER_LEN}-byte envelope header")]
    Truncated { family: Family, len: usize },
    #[error("{family} journal does not begin with the envelope magic")]
    BadMagic { family: Family },
    #[error(
        "{family} journal has envelope version {found}; this binary reads only version {VERSION}"
    )]
    UnsupportedVersion { family: Family, found: u8 },
    #[error("{family} journal carries family tag {found}, not {expected}")]
    WrongFamily {
        family: Family,
        expected: u8,
        found: u8,
    },
    #[error("{family} journal records height {found}, not the reverted block's height {expected}")]
    HeightMismatch {
        family: Family,
        expected: BlockHeight,
        found: BlockHeight,
    },
    #[error("{family} journal records block {found}, not the reverted block {expected}")]
    BlockHashMismatch {
        family: Family,
        expected: Hash,
        found: Hash,
    },
    #[error("{family} journal declares a {declared}-byte payload but carries {actual} bytes after the header")]
    LengthMismatch {
        family: Family,
        declared: usize,
        actual: usize,
    },
    #[error("{family} payload of {len} bytes does not fit the envelope's u32 length field")]
    PayloadTooLarge { family: Family, len: usize },
}

/// Seal `payload` as the undo record of the block `(height, block_hash)`.
pub fn seal(
    family: Family,
    height: BlockHeight,
    block_hash: &Hash,
    payload: &[u8],
) -> Result<Vec<u8>, EnvelopeError> {
    let len = u32::try_from(payload.len()).map_err(|_| EnvelopeError::PayloadTooLarge {
        family,
        len: payload.len(),
    })?;
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.extend_from_slice(&MAGIC);
    out.push(VERSION);
    out.push(family.tag());
    out.extend_from_slice(&height.to_be_bytes());
    out.extend_from_slice(block_hash.as_bytes());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Open a record read for the block `(height, block_hash)` and return its
/// payload, or refuse it. The identity checks run before the payload is looked
/// at, so a record for another block is never handed to a decoder.
pub fn open<'a>(
    bytes: &'a [u8],
    family: Family,
    height: BlockHeight,
    block_hash: &Hash,
) -> Result<&'a [u8], EnvelopeError> {
    if bytes.len() < HEADER_LEN {
        return Err(EnvelopeError::Truncated {
            family,
            len: bytes.len(),
        });
    }
    let (header, payload) = bytes.split_at(HEADER_LEN);
    if header[0..4] != MAGIC {
        return Err(EnvelopeError::BadMagic { family });
    }
    if header[4] != VERSION {
        return Err(EnvelopeError::UnsupportedVersion {
            family,
            found: header[4],
        });
    }
    if header[5] != family.tag() {
        return Err(EnvelopeError::WrongFamily {
            family,
            expected: family.tag(),
            found: header[5],
        });
    }
    let found_height = u64::from_be_bytes(header[6..14].try_into().expect("8-byte slice"));
    if found_height != height {
        return Err(EnvelopeError::HeightMismatch {
            family,
            expected: height,
            found: found_height,
        });
    }
    let found_hash = Hash::new(header[14..46].try_into().expect("32-byte slice"));
    if &found_hash != block_hash {
        return Err(EnvelopeError::BlockHashMismatch {
            family,
            expected: *block_hash,
            found: found_hash,
        });
    }
    let declared = u32::from_be_bytes(header[46..50].try_into().expect("4-byte slice")) as usize;
    if declared != payload.len() {
        return Err(EnvelopeError::LengthMismatch {
            family,
            declared,
            actual: payload.len(),
        });
    }
    Ok(payload)
}

/// Whether a block's record must exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expectation {
    /// The gate was open at the block's height: the publisher wrote a record,
    /// empty or not. Absence is a lost record and halts the revert.
    Required,
    /// The gate was closed: the publisher wrote nothing. A record is an anomaly
    /// no binary following these rules produces, and halts the revert.
    Absent,
}

impl Expectation {
    /// The rule for a block at `height` under a subsystem gated from `gate`.
    /// Mirrors the executor's own gate check: open from `gate` inclusive.
    pub fn at(gate: Option<BlockHeight>, height: BlockHeight) -> Self {
        match gate {
            Some(from) if height >= from => Expectation::Required,
            _ => Expectation::Absent,
        }
    }
}

/// Both subsystem gates, as the readers need them. Plain heights rather than the
/// chain parameters, so storage-level readers need no genesis dependency; the
/// caller builds it from its own `ChainParams`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SubsystemGates {
    pub compute_pool: Option<BlockHeight>,
    pub beacon: Option<BlockHeight>,
}

impl SubsystemGates {
    /// Both subsystems dormant, as on every deployed chain.
    pub const DORMANT: Self = Self {
        compute_pool: None,
        beacon: None,
    };

    pub fn expectation(&self, family: Family, height: BlockHeight) -> Expectation {
        match family {
            Family::ComputePool => Expectation::at(self.compute_pool, height),
            Family::Beacon => Expectation::at(self.beacon, height),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(b: u8) -> Hash {
        Hash::new([b; 32])
    }

    #[test]
    fn a_sealed_record_opens_only_for_its_own_block_and_family() {
        let sealed = seal(Family::ComputePool, 7, &hash(0xAA), b"payload").unwrap();
        assert_eq!(
            open(&sealed, Family::ComputePool, 7, &hash(0xAA)).unwrap(),
            b"payload"
        );
        assert!(matches!(
            open(&sealed, Family::ComputePool, 7, &hash(0xBB)),
            Err(EnvelopeError::BlockHashMismatch { .. })
        ));
        assert!(matches!(
            open(&sealed, Family::ComputePool, 8, &hash(0xAA)),
            Err(EnvelopeError::HeightMismatch { .. })
        ));
        assert!(matches!(
            open(&sealed, Family::Beacon, 7, &hash(0xAA)),
            Err(EnvelopeError::WrongFamily { .. })
        ));
    }

    #[test]
    fn the_byte_layout_is_fixed() {
        // Pinned bytes: the layout must not depend on the host's endianness or
        // word size, and CI runs this on every architecture it builds.
        let mut h = [0u8; 32];
        h[0] = 0x01;
        h[31] = 0xFF;
        let sealed = seal(
            Family::Beacon,
            0x0102_0304_0506_0708,
            &Hash::new(h),
            &[0xDE, 0xAD],
        )
        .unwrap();
        let mut want = Vec::new();
        want.extend_from_slice(b"SJR1");
        want.extend_from_slice(&[1, 2]);
        want.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        want.extend_from_slice(&h);
        want.extend_from_slice(&[0, 0, 0, 2]);
        want.extend_from_slice(&[0xDE, 0xAD]);
        assert_eq!(sealed, want);
        assert_eq!(sealed.len(), HEADER_LEN + 2);
    }

    #[test]
    fn malformed_records_are_refused() {
        let sealed = seal(Family::ComputePool, 3, &hash(1), b"abc").unwrap();
        let open3 = |b: &[u8]| open(b, Family::ComputePool, 3, &hash(1)).map(|p| p.to_vec());

        for cut in [0, 1, HEADER_LEN - 1] {
            assert!(
                matches!(open3(&sealed[..cut]), Err(EnvelopeError::Truncated { .. })),
                "cut {cut}"
            );
        }
        // Header intact, payload short.
        assert!(matches!(
            open3(&sealed[..sealed.len() - 1]),
            Err(EnvelopeError::LengthMismatch { .. })
        ));
        let mut trailing = sealed.clone();
        trailing.push(0);
        assert!(matches!(
            open3(&trailing),
            Err(EnvelopeError::LengthMismatch { .. })
        ));

        let mut magic = sealed.clone();
        magic[0] ^= 0xFF;
        assert!(matches!(open3(&magic), Err(EnvelopeError::BadMagic { .. })));

        let mut version = sealed.clone();
        version[4] = 2;
        assert!(matches!(
            open3(&version),
            Err(EnvelopeError::UnsupportedVersion { found: 2, .. })
        ));

        // An unsealed payload (what a record looked like before the envelope) is
        // refused, never decoded.
        assert!(open3(b"abc").is_err());
    }

    #[test]
    fn the_gate_decides_whether_a_record_must_exist() {
        assert_eq!(Expectation::at(None, 0), Expectation::Absent);
        assert_eq!(Expectation::at(None, u64::MAX), Expectation::Absent);
        assert_eq!(Expectation::at(Some(10), 9), Expectation::Absent);
        assert_eq!(Expectation::at(Some(10), 10), Expectation::Required);
        assert_eq!(Expectation::at(Some(10), 11), Expectation::Required);
        assert_eq!(
            SubsystemGates::DORMANT.expectation(Family::Beacon, 5),
            Expectation::Absent
        );
    }
}
