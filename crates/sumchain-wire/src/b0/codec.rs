//! Length-checked binary reader/writer and the shared decode-error type.
//!
//! Every decoder built on `Reader` rejects truncation (a read past the end) and,
//! via `Reader::finish`, trailing bytes. All multi-byte integers are little-endian.

use core::fmt;

/// All the ways a canonical B0-PRE byte structure can fail to decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// A read needed more bytes than remained.
    Truncated {
        needed: usize,
        remaining: usize,
        ctx: &'static str,
    },
    /// Bytes remained after a structure that must consume its whole buffer.
    TrailingBytes { remaining: usize, ctx: &'static str },
    /// A fixed 32-byte domain tag did not match its frozen constant.
    BadTag { ctx: &'static str },
    /// A discriminant is not a defined value of the enum.
    BadEnum { name: &'static str, value: u64 },
    /// A discriminant is a reserved-but-rejected value of the enum.
    ReservedEnum { name: &'static str, value: u64 },
    /// A fixed scalar carried a value other than its single frozen constant.
    BadFixedScalar { ctx: &'static str, value: u64 },
    /// A count field exceeds its documented maximum.
    CountExceedsMax {
        ctx: &'static str,
        count: u64,
        max: u64,
    },
    /// A length field exceeds its documented maximum.
    LengthExceedsMax {
        ctx: &'static str,
        len: u64,
        max: u64,
    },
    /// Entries that must be strictly ascending were not.
    NonCanonicalOrder { ctx: &'static str },
    /// A key/entry that must be unique repeated.
    DuplicateEntry { ctx: &'static str },
    /// Two fields that must agree (e.g. byte_len vs chunk_count) did not.
    Inconsistent { ctx: &'static str },
    /// A value fell outside its allowed domain in a way none of the above name.
    BadValue { ctx: &'static str },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::Truncated {
                needed,
                remaining,
                ctx,
            } => {
                write!(
                    f,
                    "truncated in {ctx}: needed {needed} byte(s), {remaining} remained"
                )
            }
            DecodeError::TrailingBytes { remaining, ctx } => {
                write!(
                    f,
                    "trailing bytes after {ctx}: {remaining} byte(s) left over"
                )
            }
            DecodeError::BadTag { ctx } => write!(f, "bad domain tag in {ctx}"),
            DecodeError::BadEnum { name, value } => {
                write!(f, "unknown {name} discriminant {value}")
            }
            DecodeError::ReservedEnum { name, value } => {
                write!(f, "reserved {name} discriminant {value}")
            }
            DecodeError::BadFixedScalar { ctx, value } => {
                write!(f, "non-frozen value {value} for fixed scalar {ctx}")
            }
            DecodeError::CountExceedsMax { ctx, count, max } => {
                write!(f, "count {count} exceeds max {max} in {ctx}")
            }
            DecodeError::LengthExceedsMax { ctx, len, max } => {
                write!(f, "length {len} exceeds max {max} in {ctx}")
            }
            DecodeError::NonCanonicalOrder { ctx } => write!(f, "non-canonical ordering in {ctx}"),
            DecodeError::DuplicateEntry { ctx } => write!(f, "duplicate entry in {ctx}"),
            DecodeError::Inconsistent { ctx } => write!(f, "inconsistent fields in {ctx}"),
            DecodeError::BadValue { ctx } => write!(f, "bad value in {ctx}"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// A forward-only, length-checked cursor over a byte slice.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn read_array<const N: usize>(
        &mut self,
        ctx: &'static str,
    ) -> Result<[u8; N], DecodeError> {
        if self.remaining() < N {
            return Err(DecodeError::Truncated {
                needed: N,
                remaining: self.remaining(),
                ctx,
            });
        }
        let mut out = [0u8; N];
        out.copy_from_slice(&self.buf[self.pos..self.pos + N]);
        self.pos += N;
        Ok(out)
    }

    /// Read the next `N` bytes **without advancing** the cursor. Additive,
    /// non-consuming counterpart of [`read_array`](Self::read_array): a caller can
    /// inspect a fixed-width self-domaining prefix (e.g. a carrier's 7-byte magic)
    /// to pick a sub-decoder, then let that sub-decoder re-read the same prefix.
    /// Truncation is rejected exactly as `read_array`.
    pub fn peek_array<const N: usize>(&self, ctx: &'static str) -> Result<[u8; N], DecodeError> {
        if self.remaining() < N {
            return Err(DecodeError::Truncated {
                needed: N,
                remaining: self.remaining(),
                ctx,
            });
        }
        let mut out = [0u8; N];
        out.copy_from_slice(&self.buf[self.pos..self.pos + N]);
        Ok(out)
    }

    pub fn read_bytes(&mut self, n: usize, ctx: &'static str) -> Result<&'a [u8], DecodeError> {
        if self.remaining() < n {
            return Err(DecodeError::Truncated {
                needed: n,
                remaining: self.remaining(),
                ctx,
            });
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    pub fn read_u8(&mut self, ctx: &'static str) -> Result<u8, DecodeError> {
        Ok(self.read_array::<1>(ctx)?[0])
    }
    pub fn read_u16(&mut self, ctx: &'static str) -> Result<u16, DecodeError> {
        Ok(u16::from_le_bytes(self.read_array::<2>(ctx)?))
    }
    pub fn read_u32(&mut self, ctx: &'static str) -> Result<u32, DecodeError> {
        Ok(u32::from_le_bytes(self.read_array::<4>(ctx)?))
    }
    pub fn read_u64(&mut self, ctx: &'static str) -> Result<u64, DecodeError> {
        Ok(u64::from_le_bytes(self.read_array::<8>(ctx)?))
    }

    /// Read a `u16`-length-prefixed ASCII string, rejecting over-length and any
    /// non-printable-ASCII byte.
    pub fn read_ascii_str(&mut self, max: u32, ctx: &'static str) -> Result<String, DecodeError> {
        let len = self.read_u16(ctx)? as u32;
        if len > max {
            return Err(DecodeError::LengthExceedsMax {
                ctx,
                len: len as u64,
                max: max as u64,
            });
        }
        let bytes = self.read_bytes(len as usize, ctx)?;
        if !bytes.iter().all(|&b| (0x20..=0x7E).contains(&b)) {
            return Err(DecodeError::BadValue { ctx });
        }
        Ok(String::from_utf8(bytes.to_vec()).expect("ascii"))
    }

    /// Assert the whole buffer was consumed. A canonical top-level structure is
    /// exactly its bytes; anything extra is a decode failure, not slack.
    pub fn finish(&self, ctx: &'static str) -> Result<(), DecodeError> {
        if self.remaining() != 0 {
            return Err(DecodeError::TrailingBytes {
                remaining: self.remaining(),
                ctx,
            });
        }
        Ok(())
    }
}

/// A little-endian byte sink for encoders. Length is derived from what is
/// pushed; callers assert the documented total against `len()` after encoding.
#[derive(Default, Clone)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }
    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }
    pub fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    pub fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    pub fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    pub fn bytes(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }
    pub fn tag(&mut self, t: &[u8; 32]) {
        self.buf.extend_from_slice(t);
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
    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_write_roundtrip_le() {
        let mut w = Writer::new();
        w.u8(0x12);
        w.u16(0x3456);
        w.u32(0x789a_bcde);
        w.u64(0x0102_0304_0506_0708);
        w.tag(&[0xAA; 32]);
        let bytes = w.into_bytes();
        assert_eq!(bytes.len(), 1 + 2 + 4 + 8 + 32);

        let mut r = Reader::new(&bytes);
        assert_eq!(r.read_u8("").unwrap(), 0x12);
        assert_eq!(r.read_u16("").unwrap(), 0x3456);
        assert_eq!(r.read_u32("").unwrap(), 0x789a_bcde);
        assert_eq!(r.read_u64("").unwrap(), 0x0102_0304_0506_0708);
        assert_eq!(r.read_array::<32>("").unwrap(), [0xAA; 32]);
        assert!(r.finish("").is_ok());
    }

    #[test]
    fn peek_array_does_not_advance_and_rejects_truncation() {
        let buf = [0x11u8, 0x22, 0x33, 0x44];
        let mut r = Reader::new(&buf);
        // Peeking returns the prefix but leaves the cursor untouched.
        assert_eq!(r.peek_array::<2>("").unwrap(), [0x11, 0x22]);
        assert_eq!(r.remaining(), 4);
        // A subsequent read sees the same bytes the peek reported.
        assert_eq!(r.read_array::<2>("").unwrap(), [0x11, 0x22]);
        assert_eq!(r.remaining(), 2);
        // Peeking past the end is a truncation error, like read_array.
        assert!(matches!(
            r.peek_array::<4>(""),
            Err(DecodeError::Truncated { .. })
        ));
    }

    #[test]
    fn truncation_is_rejected() {
        let buf = [0u8; 3];
        let mut r = Reader::new(&buf);
        assert!(matches!(r.read_u32(""), Err(DecodeError::Truncated { .. })));
    }

    #[test]
    fn trailing_bytes_is_rejected() {
        let buf = [0u8; 5];
        let mut r = Reader::new(&buf);
        let _ = r.read_u32("").unwrap();
        assert!(matches!(
            r.finish(""),
            Err(DecodeError::TrailingBytes { remaining: 1, .. })
        ));
    }
}
