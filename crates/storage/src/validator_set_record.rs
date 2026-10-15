//! Validator-set state row: a DORMANT, pure codec for #266.
//!
//! Nothing reads or writes this row. It has no column family, no key in any
//! existing family and no caller: the node, consensus, state and RPC crates do
//! not name it, the only other module of this crate that does is the equally
//! dormant [`crate::validator_set_state`], and this module performs no I/O.
//! `tests/validator_set_record_dormant.rs` fails if any of that changes.
//! Membership is still the static genesis list (protocol v1, #272), the legacy
//! `ValidatorSetStore` and its epoch-keyed `validator_sets` rows are untouched,
//! and the startup refusal of any stored legacy row is unchanged.
//!
//! # What it provides
//!
//! The bytes of one validator set held as ordinary application state: a row
//! written during block execution, published with the block and reverted by the
//! generic application journal (see [`crate::validator_set_state`]). Each row
//! carries a schema version, the caller's key it is stored under and the
//! ordered members, and is refused unless it agrees with the key it is read
//! under. Every malformed, foreign, truncated, extended or mismatched row is an
//! error; nothing is defaulted, skipped or repaired.
//!
//! # Why the row names no block
//!
//! The superseded version 1 (a side record staged at publication) carried its
//! own block's height and hash. A row written during execution cannot: the
//! block hash covers the state root, which execution is still computing. It
//! does not need to either: sibling blocks execute on separate overlays and
//! branch layers, so two competing blocks never share a row. Version 1 bytes
//! were never stored by any release, and this binary refuses them.
//!
//! # What is deliberately NOT decided here
//!
//! * **What the key means.** It is the caller's: an epoch number, a transition
//!   height or anything else the effective-height and transition-block
//!   decisions (#266 Q0, Q1) settle on. It is carried and checked against the
//!   row's location, never interpreted, and no value (not even 0) is refused.
//! * **Effective height.** No field says from which height the members validate
//!   blocks, whether there is an activation delay, or how either relates to
//!   finality.
//! * **Finality.** Nothing here assumes any block is, or must be, final.
//! * **Where rows live.** No column family is added: a family in
//!   [`crate::db::ALL_CFS`] is created on every node's database when it opens,
//!   and a binary without that family then refuses to open the database (see
//!   `Database::is_corruption_error`). The family and key come from the
//!   caller's layout.
//! * **Whether the row is committed.** These are storage-format bytes, not
//!   consensus bytes. Nothing folds them into a state root or a header.
//! * **The transition rule.** Who is a member and in what order is decided by
//!   whoever computes the set. The row keeps the order it is given; the only
//!   rule it applies is protocol v1's own,
//!   [`sumchain_primitives::proposer::check_validator_set`]: at least one member
//!   and no member twice.
//! * **Voting power, commission and proposer seeds.** Not carried: no protocol
//!   v1 consumer reads them (the proposer, the validator-quorum authority and the
//!   beacon membership snapshot all take an ordered list of public keys). A later
//!   version can add fields; this one refuses any other version.
//!
//! # Row format (version 2)
//!
//! ```text
//! offset  size  field
//!      0     4  magic          b"SVSR"
//!      4     2  version        u16, big-endian, = 2
//!      6     8  key            u64, big-endian
//!     14     4  member count   u32, big-endian, >= 1
//!     18  32*n  members        public keys, in row order
//! ```
//!
//! Exactly `18 + 32 * n` bytes. Fixed widths, so every accepted row has one
//! encoding and re-encodes to the bytes it was read from. Big-endian like the
//! other storage records in this crate.

use sumchain_primitives::proposer::{check_validator_set, ProposerSelectionError};

/// First four bytes of every row.
pub const MAGIC: [u8; 4] = *b"SVSR";

/// The only row version this binary writes or reads. Version 1 was the
/// superseded side-record layout, which no release stored.
pub const VERSION: u16 = 2;

/// Bytes before the first member.
pub const HEADER_LEN: usize = 4 + 2 + 8 + 4;

/// Length of one member public key.
const MEMBER_LEN: usize = 32;

/// Why a row was refused. Every variant is a refusal: no caller may treat one
/// as "no set here".
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ValidatorSetRecordError {
    #[error("validator-set row is {len} bytes, shorter than its {HEADER_LEN}-byte header")]
    Truncated { len: usize },
    #[error("validator-set row does not begin with its magic")]
    BadMagic,
    #[error("validator-set row has version {found}; this binary reads only version {VERSION}")]
    UnsupportedVersion { found: u16 },
    #[error("validator-set row read under key {expected} records key {found}")]
    KeyMismatch { expected: u64, found: u64 },
    #[error(
        "validator-set row declares {declared} member(s) but carries {actual} byte(s) of \
         members; each member is {MEMBER_LEN} bytes"
    )]
    LengthMismatch { declared: u32, actual: usize },
    #[error("validator-set row has {count} members, more than its u32 count field holds")]
    TooManyMembers { count: usize },
    #[error("validator-set row members are not a protocol v1 validator set: {0}")]
    InvalidMembers(ProposerSelectionError),
}

/// One validator set, under the caller's key.
///
/// Fields are private so that every value in hand has passed
/// [`ValidatorSetRecord::new`] or a decode: the member list is non-empty and
/// distinct, and its length fits the row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorSetRecord {
    key: u64,
    members: Vec<[u8; 32]>,
}

impl ValidatorSetRecord {
    /// A row for `key`. Refuses a member list protocol v1 could not rotate
    /// over (empty, or a member twice) and one too long for the count field.
    /// The order given is kept.
    pub fn new(key: u64, members: Vec<[u8; 32]>) -> Result<Self, ValidatorSetRecordError> {
        if u32::try_from(members.len()).is_err() {
            return Err(ValidatorSetRecordError::TooManyMembers {
                count: members.len(),
            });
        }
        check_validator_set(&members).map_err(ValidatorSetRecordError::InvalidMembers)?;
        Ok(Self { key, members })
    }

    /// Carried, not interpreted: see the module documentation.
    pub fn key(&self) -> u64 {
        self.key
    }

    /// The members, in row order.
    pub fn members(&self) -> &[[u8; 32]] {
        &self.members
    }

    /// The row's only encoding.
    pub fn encode(&self) -> Vec<u8> {
        let count = u32::try_from(self.members.len()).expect("checked by every constructor");
        let mut out = Vec::with_capacity(HEADER_LEN + MEMBER_LEN * self.members.len());
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&VERSION.to_be_bytes());
        out.extend_from_slice(&self.key.to_be_bytes());
        out.extend_from_slice(&count.to_be_bytes());
        for member in &self.members {
            out.extend_from_slice(member);
        }
        out
    }

    /// Decode a row read under `key`, or refuse it.
    ///
    /// The key check runs before the members are looked at, so a row stored
    /// under another key is refused as such rather than for whatever else may
    /// be wrong with it. The member bytes must be exactly what the count
    /// declares: a short row and a row with trailing bytes are both refused,
    /// and nothing is allocated for members until the length agrees.
    pub fn decode_for(bytes: &[u8], key: u64) -> Result<Self, ValidatorSetRecordError> {
        if bytes.len() < HEADER_LEN {
            return Err(ValidatorSetRecordError::Truncated { len: bytes.len() });
        }
        let (header, body) = bytes.split_at(HEADER_LEN);
        if header[0..4] != MAGIC {
            return Err(ValidatorSetRecordError::BadMagic);
        }
        let version = u16::from_be_bytes(header[4..6].try_into().expect("2-byte slice"));
        if version != VERSION {
            return Err(ValidatorSetRecordError::UnsupportedVersion { found: version });
        }
        let found = u64::from_be_bytes(header[6..14].try_into().expect("8-byte slice"));
        if found != key {
            return Err(ValidatorSetRecordError::KeyMismatch {
                expected: key,
                found,
            });
        }
        let declared = u32::from_be_bytes(header[14..18].try_into().expect("4-byte slice"));
        // In u64: a u32 count times 32 cannot overflow it on any target.
        if declared as u64 * MEMBER_LEN as u64 != body.len() as u64 {
            return Err(ValidatorSetRecordError::LengthMismatch {
                declared,
                actual: body.len(),
            });
        }
        let members: Vec<[u8; 32]> = body
            .chunks_exact(MEMBER_LEN)
            .map(|m| m.try_into().expect("32-byte chunk"))
            .collect();
        check_validator_set(&members).map_err(ValidatorSetRecordError::InvalidMembers)?;
        Ok(Self { key, members })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sumchain_primitives::ValidatorSet;

    fn member(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn record() -> ValidatorSetRecord {
        ValidatorSetRecord::new(14_400, vec![member(3), member(1), member(2)]).unwrap()
    }

    #[test]
    fn a_row_round_trips_under_its_own_key_and_keeps_member_order() {
        let r = record();
        let bytes = r.encode();
        let back = ValidatorSetRecord::decode_for(&bytes, 14_400).unwrap();
        assert_eq!(back, r);
        assert_eq!(back.members(), &[member(3), member(1), member(2)]);
        assert_eq!(back.key(), 14_400);
        // One encoding per row: what was accepted re-encodes to itself.
        assert_eq!(back.encode(), bytes);
    }

    #[test]
    fn the_row_layout_is_fixed() {
        let r = ValidatorSetRecord::new(0x0102_0304_0506_0708, vec![member(0xA1), member(0xB2)])
            .unwrap();
        let mut want = Vec::new();
        want.extend_from_slice(b"SVSR");
        want.extend_from_slice(&[0, 2]);
        want.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        want.extend_from_slice(&[0, 0, 0, 2]);
        want.extend_from_slice(&[0xA1; 32]);
        want.extend_from_slice(&[0xB2; 32]);
        assert_eq!(r.encode(), want);
        assert_eq!(want.len(), HEADER_LEN + 2 * 32);
        assert_eq!(HEADER_LEN, 18);
        // And in the other direction: the pinned bytes decode to the row.
        assert_eq!(
            ValidatorSetRecord::decode_for(&want, 0x0102_0304_0506_0708).unwrap(),
            r
        );
    }

    #[test]
    fn a_row_read_under_another_key_is_refused() {
        let a = ValidatorSetRecord::new(7, vec![member(1)]).unwrap();
        assert_eq!(
            ValidatorSetRecord::decode_for(&a.encode(), 8),
            Err(ValidatorSetRecordError::KeyMismatch {
                expected: 8,
                found: 7
            })
        );
    }

    #[test]
    fn every_truncation_and_every_extension_is_refused() {
        let bytes = record().encode();
        let open = |b: &[u8]| ValidatorSetRecord::decode_for(b, 14_400);
        for cut in 0..bytes.len() {
            let err = open(&bytes[..cut]).unwrap_err();
            if cut < HEADER_LEN {
                assert_eq!(
                    err,
                    ValidatorSetRecordError::Truncated { len: cut },
                    "cut {cut}"
                );
            } else {
                assert!(
                    matches!(
                        err,
                        ValidatorSetRecordError::LengthMismatch { declared: 3, .. }
                    ),
                    "cut {cut}: {err}"
                );
            }
        }
        for extra in [1usize, 31, 32, 33] {
            let mut long = bytes.clone();
            long.resize(long.len() + extra, 0x5A);
            assert!(
                matches!(
                    open(&long),
                    Err(ValidatorSetRecordError::LengthMismatch { declared: 3, .. })
                ),
                "extra {extra}"
            );
        }
    }

    #[test]
    fn foreign_and_unknown_version_rows_are_refused() {
        let bytes = record().encode();
        let open = |b: &[u8]| ValidatorSetRecord::decode_for(b, 14_400);

        let mut magic = bytes.clone();
        magic[0] ^= 0xFF;
        assert_eq!(open(&magic), Err(ValidatorSetRecordError::BadMagic));

        for v in [0u16, 1, 3, u16::MAX] {
            let mut version = bytes.clone();
            version[4..6].copy_from_slice(&v.to_be_bytes());
            assert_eq!(
                open(&version),
                Err(ValidatorSetRecordError::UnsupportedVersion { found: v })
            );
        }

        // The legacy epoch-keyed row format (bincode `ValidatorSet`) is never
        // read as a row.
        let legacy = bincode::serialize(&ValidatorSet::new(
            1,
            14_400,
            vec![sumchain_primitives::ValidatorSetEntry::new(member(1), 1, 0)],
            [0u8; 32],
        ))
        .unwrap();
        assert!(open(&legacy).is_err());
    }

    #[test]
    fn the_superseded_side_record_is_refused_by_its_version() {
        // Version 1 framing: magic, version 1, height, block hash, epoch,
        // count, members. No release wrote it; this binary must not read it as
        // a state row.
        let mut v1 = Vec::new();
        v1.extend_from_slice(b"SVSR");
        v1.extend_from_slice(&1u16.to_be_bytes());
        v1.extend_from_slice(&14_400u64.to_be_bytes());
        v1.extend_from_slice(&[0xAA; 32]);
        v1.extend_from_slice(&1u64.to_be_bytes());
        v1.extend_from_slice(&1u32.to_be_bytes());
        v1.extend_from_slice(&member(1));
        assert_eq!(
            ValidatorSetRecord::decode_for(&v1, 14_400),
            Err(ValidatorSetRecordError::UnsupportedVersion { found: 1 })
        );
    }

    #[test]
    fn a_count_that_disagrees_with_the_members_is_refused_without_allocating() {
        let bytes = record().encode();
        let open = |b: &[u8]| ValidatorSetRecord::decode_for(b, 14_400);
        for declared in [0u32, 2, 4, u32::MAX] {
            let mut lying = bytes.clone();
            lying[14..18].copy_from_slice(&declared.to_be_bytes());
            assert_eq!(
                open(&lying),
                Err(ValidatorSetRecordError::LengthMismatch {
                    declared,
                    actual: 3 * 32
                }),
                "declared {declared}"
            );
        }
    }

    #[test]
    fn empty_or_duplicated_member_lists_are_refused_on_both_sides() {
        assert!(matches!(
            ValidatorSetRecord::new(1, vec![]),
            Err(ValidatorSetRecordError::InvalidMembers(
                ProposerSelectionError::EmptyValidatorSet
            ))
        ));
        assert!(matches!(
            ValidatorSetRecord::new(1, vec![member(1), member(2), member(1)]),
            Err(ValidatorSetRecordError::InvalidMembers(
                ProposerSelectionError::DuplicateValidator {
                    first: 0,
                    second: 2
                }
            ))
        ));

        // Hand-built bytes a constructor would never produce.
        let header = |count: u32| {
            let mut b = Vec::new();
            b.extend_from_slice(&MAGIC);
            b.extend_from_slice(&VERSION.to_be_bytes());
            b.extend_from_slice(&5u64.to_be_bytes());
            b.extend_from_slice(&count.to_be_bytes());
            b
        };
        assert!(matches!(
            ValidatorSetRecord::decode_for(&header(0), 5),
            Err(ValidatorSetRecordError::InvalidMembers(
                ProposerSelectionError::EmptyValidatorSet
            ))
        ));
        let mut dup = header(2);
        dup.extend_from_slice(&member(4));
        dup.extend_from_slice(&member(4));
        assert!(matches!(
            ValidatorSetRecord::decode_for(&dup, 5),
            Err(ValidatorSetRecordError::InvalidMembers(
                ProposerSelectionError::DuplicateValidator { .. }
            ))
        ));
    }

    #[test]
    fn the_key_is_not_interpreted_by_this_codec() {
        // What the key means (an epoch, a height or anything else) is an open
        // decision (#266 Q0, Q1). The codec takes no position: any key,
        // including 0 and u64::MAX, round-trips.
        for key in [0, 1, 14_399, 14_400, u64::MAX] {
            let r = ValidatorSetRecord::new(key, vec![member(1)]).unwrap();
            let back = ValidatorSetRecord::decode_for(&r.encode(), key).unwrap();
            assert_eq!(back.key(), key);
        }
    }
}
