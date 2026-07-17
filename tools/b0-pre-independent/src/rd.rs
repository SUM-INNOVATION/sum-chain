//! Independent length-checked reader (distinct from the reference's `codec`).

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum E {
    Short,
    Trailing,
    BadTag,
    BadEnum,
    Order,
    Dup,
    Count,
    Range,
    Value,
    Inconsistent,
}

pub struct Rd<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Rd<'a> {
    pub fn new(b: &'a [u8]) -> Self {
        Self { b, p: 0 }
    }
    pub fn left(&self) -> usize {
        self.b.len() - self.p
    }
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], E> {
        if self.left() < n {
            return Err(E::Short);
        }
        let s = &self.b[self.p..self.p + n];
        self.p += n;
        Ok(s)
    }
    pub fn arr<const N: usize>(&mut self) -> Result<[u8; N], E> {
        let s = self.take(N)?;
        let mut o = [0u8; N];
        o.copy_from_slice(s);
        Ok(o)
    }
    pub fn u8(&mut self) -> Result<u8, E> {
        Ok(self.arr::<1>()?[0])
    }
    pub fn u16(&mut self) -> Result<u16, E> {
        Ok(u16::from_le_bytes(self.arr::<2>()?))
    }
    pub fn u32(&mut self) -> Result<u32, E> {
        Ok(u32::from_le_bytes(self.arr::<4>()?))
    }
    pub fn u64(&mut self) -> Result<u64, E> {
        Ok(u64::from_le_bytes(self.arr::<8>()?))
    }
    pub fn tag32(&mut self, expected: &[u8; 32]) -> Result<(), E> {
        let t = self.arr::<32>()?;
        if &t != expected {
            return Err(E::BadTag);
        }
        Ok(())
    }
    /// Read a `u16`-length-prefixed printable-ASCII string, bounded by `max`.
    pub fn str16(&mut self, max: u32) -> Result<String, E> {
        let n = self.u16()? as u32;
        if n > max {
            return Err(E::Range);
        }
        let s = self.take(n as usize)?;
        if !s.iter().all(|&b| (0x20..=0x7E).contains(&b)) {
            return Err(E::Value);
        }
        Ok(String::from_utf8(s.to_vec()).expect("ascii"))
    }
    pub fn end(&self) -> Result<(), E> {
        if self.left() != 0 {
            Err(E::Trailing)
        } else {
            Ok(())
        }
    }
}
