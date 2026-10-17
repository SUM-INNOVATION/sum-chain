//! G2 group A1 encoding conventions, RATIFIED 2026-10-17 (D0, D4). DORMANT.
//!
//! * **D0.** Integers are little-endian in every new finality and upgrade
//!   object, signed preimage and record. They are big-endian only in database
//!   keys, so that keys sort numerically. The two orders have separate types
//!   ([`LeWriter`]/[`LeReader`] and [`KeyWriter`]/[`KeyReader`]) so an object
//!   encoder can never emit a big-endian integer, and a key encoder can never
//!   emit a little-endian one. The frozen `protocol_digest` keeps its own
//!   big-endian encoder and shares nothing with this module.
//! * **D4.** Every round field is a `u32` with the validity rule
//!   `round ≤ 2^20` ([`Round`]), enforced at construction and at decode.
//!
//! Strict decoding: exact lengths (a short read is refused), no trailing
//! bytes ([`LeReader::finish`], [`KeyReader::finish`]), flag bytes 0 or 1
//! only, and absent groups all zero.
//!
//! # Not here (unratified)
//!
//! No object layout is frozen by this module: not the vote, certificate,
//! signer state, evidence, manifest or hint, and not the composition of any
//! database key. Those are A2–A5 and the object layouts, still under review.
//! These helpers are the conventions those layouts will be written in.

use thiserror::Error;

/// D4: the largest valid round, `2^20`.
pub const MAX_ROUND: u32 = 1 << 20;

/// A round number, valid only when `≤ 2^20` (D4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Round(u32);

/// A round above `2^20` (D4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("round {0} exceeds the D4 cap 2^20")]
pub struct RoundOutOfRange(pub u32);

impl Round {
    /// Round 0.
    pub const ZERO: Round = Round(0);
    /// Round `2^20`, the largest valid round.
    pub const MAX: Round = Round(MAX_ROUND);

    /// A round, refused above `2^20`.
    pub const fn new(value: u32) -> Result<Round, RoundOutOfRange> {
        if value > MAX_ROUND {
            Err(RoundOutOfRange(value))
        } else {
            Ok(Round(value))
        }
    }

    /// The round as a `u32`.
    pub const fn get(self) -> u32 {
        self.0
    }

    /// The next round, or `None` at the cap.
    pub fn next(self) -> Option<Round> {
        Round::new(self.0.checked_add(1)?).ok()
    }
}

impl TryFrom<u32> for Round {
    type Error = RoundOutOfRange;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Round::new(value)
    }
}

impl From<Round> for u32 {
    fn from(round: Round) -> u32 {
        round.0
    }
}

/// Why a strict decode refused its input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DecodeError {
    #[error("truncated: needed {needed} bytes, {remaining} remain")]
    Truncated { needed: usize, remaining: usize },
    #[error("{0} trailing bytes after the last field")]
    Trailing(usize),
    #[error(transparent)]
    Round(#[from] RoundOutOfRange),
    #[error("flag byte {0:#04x} is neither 0 nor 1")]
    BadFlag(u8),
    #[error("an absent group of {0} bytes is not all zero")]
    NonZeroAbsentGroup(usize),
}

/// Little-endian encoder for objects, signed preimages and records (D0).
#[derive(Debug, Default, Clone)]
pub struct LeWriter {
    buf: Vec<u8>,
}

impl LeWriter {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }
    pub fn u16(&mut self, v: u16) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }
    /// A round field: `u32` little-endian (D0, D4).
    pub fn round(&mut self, r: Round) -> &mut Self {
        self.u32(r.get())
    }
    /// A flag byte: 1 or 0.
    pub fn flag(&mut self, v: bool) -> &mut Self {
        self.u8(u8::from(v))
    }
    /// An absent group of `len` bytes, written as zeros.
    pub fn zeros(&mut self, len: usize) -> &mut Self {
        self.buf.resize(self.buf.len() + len, 0);
        self
    }
    pub fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(b);
        self
    }
    pub fn len(&self) -> usize {
        self.buf.len()
    }
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }
}

/// Strict little-endian decoder for objects, signed preimages and records (D0).
#[derive(Debug, Clone)]
pub struct LeReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

/// Strict big-endian decoder for database keys (D0).
#[derive(Debug, Clone)]
pub struct KeyReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

macro_rules! strict_reader {
    ($ty:ident, $from:ident) => {
        impl<'a> $ty<'a> {
            pub fn new(buf: &'a [u8]) -> Self {
                Self { buf, pos: 0 }
            }
            /// Bytes not yet read.
            pub fn remaining(&self) -> usize {
                self.buf.len() - self.pos
            }
            fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
                let remaining = self.remaining();
                if n > remaining {
                    return Err(DecodeError::Truncated {
                        needed: n,
                        remaining,
                    });
                }
                let out = &self.buf[self.pos..self.pos + n];
                self.pos += n;
                Ok(out)
            }
            pub fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
                let mut out = [0u8; N];
                out.copy_from_slice(self.take(N)?);
                Ok(out)
            }
            pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
                self.take(n)
            }
            pub fn u8(&mut self) -> Result<u8, DecodeError> {
                Ok(self.array::<1>()?[0])
            }
            pub fn u16(&mut self) -> Result<u16, DecodeError> {
                Ok(u16::$from(self.array()?))
            }
            pub fn u32(&mut self) -> Result<u32, DecodeError> {
                Ok(u32::$from(self.array()?))
            }
            pub fn u64(&mut self) -> Result<u64, DecodeError> {
                Ok(u64::$from(self.array()?))
            }
            /// A round field, refused above `2^20` (D4).
            pub fn round(&mut self) -> Result<Round, DecodeError> {
                Ok(Round::new(self.u32()?)?)
            }
            /// End of input: any trailing byte is refused.
            pub fn finish(self) -> Result<(), DecodeError> {
                match self.remaining() {
                    0 => Ok(()),
                    n => Err(DecodeError::Trailing(n)),
                }
            }
        }
    };
}

strict_reader!(LeReader, from_le_bytes);
strict_reader!(KeyReader, from_be_bytes);

impl LeReader<'_> {
    /// A flag byte: exactly 0 or 1.
    pub fn flag(&mut self) -> Result<bool, DecodeError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            b => Err(DecodeError::BadFlag(b)),
        }
    }
    /// An absent group of `len` bytes: it must be all zero.
    pub fn zeros(&mut self, len: usize) -> Result<(), DecodeError> {
        if self.take(len)?.iter().all(|&b| b == 0) {
            Ok(())
        } else {
            Err(DecodeError::NonZeroAbsentGroup(len))
        }
    }
}

/// Big-endian encoder for database keys only (D0), so that keys sort
/// numerically. Never use it for an object, preimage or record.
#[derive(Debug, Default, Clone)]
pub struct KeyWriter {
    buf: Vec<u8>,
}

impl KeyWriter {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }
    pub fn u16(&mut self, v: u16) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }
    /// A round in a key: `u32` big-endian (D0, D4).
    pub fn round(&mut self, r: Round) -> &mut Self {
        self.u32(r.get())
    }
    pub fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(b);
        self
    }
    pub fn len(&self) -> usize {
        self.buf.len()
    }
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }
}
