//! Address type for SUM Chain accounts.
//!
//! Addresses are derived from Ed25519 public keys using Blake3,
//! taking the last 20 bytes. Displayed in base58 with a checksum.
//!
//! ## Text forms
//!
//! An address has two text forms, both naming the same 20 bytes (sum-chain #309,
//! SwUM specification 5.2, decision D2):
//!
//! - the plain form, [`Address::to_base58`]: base58 of the bytes followed by a
//!   4-byte checksum;
//! - the agent form ("raddress"), [`Address::to_raddress`]: the two characters
//!   `r0` followed by the plain form, unchanged — the same bytes, key and
//!   checksum.
//!
//! `0` is not in the base58 alphabet, so no plain address begins with `r0` and
//! the two forms never overlap. [`AddressText`] parses either and records which
//! one was written. The form is text only: no encoded byte, hash, signature or
//! state key involves it, and nothing on chain says which accounts are agents.
//! `r0` is a text form only; it does not identify an agent or grant anything.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;
#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};

use crate::{PrimitiveError, Result};

/// 20-byte address derived from public key
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, PartialOrd, Ord)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct Address([u8; 20]);

impl Address {
    /// Size of address in bytes
    pub const SIZE: usize = 20;

    /// Zero address (for coinbase/system operations)
    pub const ZERO: Address = Address([0u8; 20]);

    /// Create address from raw bytes
    pub fn new(bytes: [u8; 20]) -> Self {
        Address(bytes)
    }

    /// Create address from a slice
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != Self::SIZE {
            return Err(PrimitiveError::InvalidLength {
                expected: Self::SIZE,
                got: slice.len(),
            });
        }
        let mut bytes = [0u8; 20];
        bytes.copy_from_slice(slice);
        Ok(Address(bytes))
    }

    /// Derive address from a public key (32 bytes for Ed25519)
    /// Takes Blake3 hash of pubkey, then last 20 bytes
    pub fn from_public_key(pubkey: &[u8; 32]) -> Self {
        let hash = blake3::hash(pubkey);
        let hash_bytes = hash.as_bytes();
        let mut bytes = [0u8; 20];
        bytes.copy_from_slice(&hash_bytes[12..32]); // Last 20 bytes
        Address(bytes)
    }

    /// Parse address from base58 string with checksum
    /// Format: base58(address_bytes + checksum[0..4])
    pub fn from_base58(s: &str) -> Result<Self> {
        let decoded = bs58::decode(s)
            .into_vec()
            .map_err(|e| PrimitiveError::InvalidBase58(e.to_string()))?;

        if decoded.len() != Self::SIZE + 4 {
            return Err(PrimitiveError::InvalidLength {
                expected: Self::SIZE + 4,
                got: decoded.len(),
            });
        }

        let (addr_bytes, checksum) = decoded.split_at(Self::SIZE);

        // Verify checksum: first 4 bytes of Blake3(Blake3(addr_bytes))
        let hash1 = blake3::hash(addr_bytes);
        let hash2 = blake3::hash(hash1.as_bytes());

        if &hash2.as_bytes()[0..4] != checksum {
            return Err(PrimitiveError::InvalidChecksum);
        }

        Self::from_slice(addr_bytes)
    }

    /// Convert to base58 string with checksum
    pub fn to_base58(&self) -> String {
        let hash1 = blake3::hash(&self.0);
        let hash2 = blake3::hash(hash1.as_bytes());

        let mut with_checksum = Vec::with_capacity(Self::SIZE + 4);
        with_checksum.extend_from_slice(&self.0);
        with_checksum.extend_from_slice(&hash2.as_bytes()[0..4]);

        bs58::encode(with_checksum).into_string()
    }

    /// Convert to the agent text form ("raddress"): `r0` followed by
    /// [`Address::to_base58`], unchanged. A text form only; it does not
    /// identify an agent or grant anything. See the [module docs](self).
    pub fn to_raddress(&self) -> String {
        format!("r0{}", self.to_base58())
    }

    /// Create from hex string
    pub fn from_hex(s: &str) -> Result<Self> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(s).map_err(|e| PrimitiveError::InvalidHex(e.to_string()))?;
        Self::from_slice(&bytes)
    }

    /// Convert to hex string (with 0x prefix)
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.0))
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }

    /// Check if this is the zero address
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 20]
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address({})", self.to_base58())
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_base58())
    }
}

impl AsRef<[u8]> for Address {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 20]> for Address {
    fn from(bytes: [u8; 20]) -> Self {
        Address(bytes)
    }
}

/// An address together with the text form it was written in.
///
/// The variant records the form of the text, not a fact about the account:
/// `Agent` means the text carried the `r0` prefix, `Human` means it did not.
/// Both hold the same [`Address`] for the same key; compare with
/// [`AddressText::address`] when only the account matters.
///
/// `r0` is a text form only; it does not identify an agent or grant anything.
/// No permission, signature, fee or account rule may read the variant: those
/// work on the [`Address`]. A caller may refuse a form it does not expect, as a
/// check on its input and nothing more.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AddressText {
    /// The plain base58 form ([`Address::to_base58`]).
    Human(Address),
    /// The agent form ([`Address::to_raddress`]): `r0` then the plain form.
    Agent(Address),
}

impl AddressText {
    /// Parse the plain base58 form or the agent (`r0`) form.
    ///
    /// The `r0` prefix is decided first: text that starts with it is the agent
    /// form or an error, never retried as plain text. The base58 text is not of
    /// fixed length: it encodes 24 bytes (the address and a 4-byte checksum), so
    /// it is 24 to 33 characters: most addresses take 33, some 32, and only an
    /// address with two or more leading zero bytes takes fewer
    /// ([`Address::ZERO`] takes 26). It is decoded and its length and checksum
    /// checked by [`Address::from_base58`].
    pub fn parse(s: &str) -> Result<Self> {
        match s.strip_prefix("r0") {
            Some(plain) => Address::from_base58(plain).map(AddressText::Agent),
            None => Address::from_base58(s).map(AddressText::Human),
        }
    }

    /// As [`AddressText::parse`], and also hex ([`Address::from_hex`], `0x`
    /// optional), which parses as `Human`: only the `r0` prefix marks the agent
    /// form. Text that starts with `r0` is never retried as hex (`r` is not a
    /// hex digit, so it could never be hex either).
    ///
    /// For input that does not start with `r0` the result, and the error, are
    /// those of `Address::from_base58(s).or_else(|_| Address::from_hex(s))`.
    pub fn parse_or_hex(s: &str) -> Result<Self> {
        match s.strip_prefix("r0") {
            Some(plain) => Address::from_base58(plain).map(AddressText::Agent),
            None => Address::from_base58(s)
                .or_else(|_| Address::from_hex(s))
                .map(AddressText::Human),
        }
    }

    /// The address, whichever form it was written in.
    pub fn address(self) -> Address {
        match self {
            AddressText::Human(a) | AddressText::Agent(a) => a,
        }
    }

    /// Whether the text was the agent (`r0`) form. It says nothing about the
    /// account: the text form only.
    pub fn is_agent(self) -> bool {
        matches!(self, AddressText::Agent(_))
    }
}

/// Writes the form that was parsed: [`Address::to_base58`] for `Human`,
/// [`Address::to_raddress`] for `Agent`.
impl fmt::Display for AddressText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AddressText::Human(a) => f.write_str(&a.to_base58()),
            AddressText::Agent(a) => f.write_str(&a.to_raddress()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_public_key() {
        let pubkey = [0u8; 32];
        let addr = Address::from_public_key(&pubkey);
        assert!(!addr.is_zero()); // Hash of zeros is not zero
    }

    #[test]
    fn test_base58_roundtrip() {
        let addr = Address::from_public_key(&[42u8; 32]);
        let b58 = addr.to_base58();
        let addr2 = Address::from_base58(&b58).unwrap();
        assert_eq!(addr, addr2);
    }

    #[test]
    fn test_hex_roundtrip() {
        let addr = Address::from_public_key(&[1u8; 32]);
        let hex = addr.to_hex();
        let addr2 = Address::from_hex(&hex).unwrap();
        assert_eq!(addr, addr2);
    }

    #[test]
    fn test_invalid_checksum() {
        let addr = Address::from_public_key(&[1u8; 32]);
        let mut b58 = addr.to_base58();

        // Corrupt the string
        let chars: Vec<char> = b58.chars().collect();
        let last = chars.last().unwrap();
        let new_last = if *last == 'a' { 'b' } else { 'a' };
        b58.pop();
        b58.push(new_last);

        let result = Address::from_base58(&b58);
        assert!(result.is_err());
    }

    #[test]
    fn test_zero_address() {
        assert!(Address::ZERO.is_zero());
    }

    // ── text forms (#309) ──────────────────────────────────────────────────
    //
    // Deterministic table-and-loop checks; the crate has no property-testing
    // dependency.

    /// `n` addresses from distinct keys, in a fixed order.
    fn sample(n: u32) -> Vec<Address> {
        (0..n)
            .map(|i| {
                let mut pubkey = [0u8; 32];
                pubkey[..4].copy_from_slice(&i.to_le_bytes());
                Address::from_public_key(&pubkey)
            })
            .collect()
    }

    /// Addresses whose plain text is unusually short or long.
    fn edges() -> Vec<Address> {
        let mut leading_zero = [0x5Au8; 20];
        leading_zero[0] = 0;
        vec![
            Address::ZERO,
            Address::new([0xFF; 20]),
            Address::new(leading_zero),
            Address::new({
                let mut b = [0u8; 20];
                b[19] = 1;
                b
            }),
        ]
    }

    fn assert_both_forms_round_trip(a: Address) {
        let plain = a.to_base58();
        let agent = a.to_raddress();
        assert_eq!(agent, format!("r0{plain}"));

        let h = AddressText::parse(&plain).unwrap();
        let g = AddressText::parse(&agent).unwrap();
        assert_eq!(h, AddressText::Human(a));
        assert_eq!(g, AddressText::Agent(a));
        assert!(!h.is_agent());
        assert!(g.is_agent());
        // One key, two forms: the same Address, distinct texts.
        assert_eq!(h.address(), g.address());
        assert_ne!(h, g);
        // Display writes back exactly the text that was parsed.
        assert_eq!(h.to_string(), plain);
        assert_eq!(g.to_string(), agent);
        // parse_or_hex agrees on both base58 forms and reads hex as Human.
        assert_eq!(AddressText::parse_or_hex(&plain).unwrap(), h);
        assert_eq!(AddressText::parse_or_hex(&agent).unwrap(), g);
        assert_eq!(AddressText::parse_or_hex(&a.to_hex()).unwrap(), h);
        assert_eq!(
            AddressText::parse_or_hex(a.to_hex().trim_start_matches("0x")).unwrap(),
            h
        );
    }

    #[test]
    fn text_forms_round_trip_and_have_no_fixed_length() {
        let mut by_len = std::collections::BTreeMap::<usize, usize>::new();
        for a in sample(4096) {
            let plain = a.to_base58();
            // `0` is not base58, so no plain address can look like an agent one.
            assert!(!plain.starts_with("r0"), "{plain}");
            *by_len.entry(plain.len()).or_default() += 1;
            assert_both_forms_round_trip(a);
        }
        // Both common plain lengths occur, so neither may be assumed.
        assert!(by_len.contains_key(&32), "no 32-character address: {by_len:?}");
        assert!(by_len.contains_key(&33), "no 33-character address: {by_len:?}");
        assert!(by_len.keys().all(|&n| n <= 33), "{by_len:?}");

        for a in edges() {
            assert_both_forms_round_trip(a);
        }
        // Leading zero bytes shorten the text well below 32 characters.
        assert!(Address::ZERO.to_base58().len() < 32);
    }

    #[test]
    fn r0_followed_by_anything_but_a_plain_address_is_refused() {
        let a = Address::from_public_key(&[7u8; 32]);
        let plain = a.to_base58();
        let mut bad_checksum = plain.clone();
        let last = bad_checksum.pop().unwrap();
        bad_checksum.push(if last == 'a' { 'b' } else { 'a' });
        let hex = a.to_hex();

        let refused = [
            "r0".to_string(),                              // nothing after the prefix
            format!("r0{}", &plain[..plain.len() - 1]),    // truncated
            format!("r0{plain}1"),                         // one character too many
            format!("r0{bad_checksum}"),                   // checksum fails
            format!("r0{}0", &plain[..plain.len() - 1]),   // `0` is not base58
            format!("r0{}O", &plain[..plain.len() - 1]),   // `O` is not base58
            format!("r0{}l", &plain[..plain.len() - 1]),   // `l` is not base58
            format!("r0{hex}"),                            // the agent form is not over hex
            format!("r0{}", hex.trim_start_matches("0x")), // nor over bare hex
            format!("r0r0{plain}"),                        // one prefix only
            format!("R0{plain}"),                          // the prefix is lower-case
            format!("r1{plain}"),                          // a different prefix
            format!(" r0{plain}"),                         // no trimming
            format!("r0 {plain}"),
            format!("r0{plain} "),
        ];
        for s in &refused {
            assert!(AddressText::parse(s).is_err(), "parse accepted {s:?}");
            assert!(AddressText::parse_or_hex(s).is_err(), "parse_or_hex accepted {s:?}");
        }
        // The agent form is never read as hex, and hex is not a parse form.
        assert!(AddressText::parse(&hex).is_err());
        // Sanity: the unmodified agent form is accepted.
        assert_eq!(AddressText::parse(&format!("r0{plain}")).unwrap(), AddressText::Agent(a));
    }

    #[test]
    fn parse_or_hex_matches_the_base58_then_hex_rule_off_the_prefix() {
        let a = Address::from_public_key(&[9u8; 32]);
        let old = |s: &str| Address::from_base58(s).or_else(|_| Address::from_hex(s));
        let inputs = [
            a.to_base58(),
            a.to_hex(),
            a.to_hex().trim_start_matches("0x").to_string(),
            String::new(),
            "notanaddress".to_string(),
            "0x1234".to_string(),
            "0xzz".to_string(),
            "1111".to_string(),
        ];
        for s in &inputs {
            match (old(s), AddressText::parse_or_hex(s)) {
                (Ok(x), Ok(t)) => assert_eq!(t, AddressText::Human(x), "{s:?}"),
                (Err(e1), Err(e2)) => assert_eq!(e1.to_string(), e2.to_string(), "{s:?}"),
                (o, n) => panic!("{s:?}: old {o:?}, new {n:?}"),
            }
            match (Address::from_base58(s), AddressText::parse(s)) {
                (Ok(x), Ok(t)) => assert_eq!(t, AddressText::Human(x), "{s:?}"),
                (Err(e1), Err(e2)) => assert_eq!(e1.to_string(), e2.to_string(), "{s:?}"),
                (o, n) => panic!("{s:?}: old {o:?}, new {n:?}"),
            }
        }
    }

    /// `r0` is a text form only: one key gives one `Address` in either form,
    /// with the same bytes, the same wire encoding and the same hash-map key,
    /// so nothing downstream of the parser can tell the forms apart.
    #[test]
    fn one_key_gives_one_address_in_either_form() {
        use std::collections::HashSet;
        for i in 0u32..64 {
            let mut pubkey = [0u8; 32];
            pubkey[..4].copy_from_slice(&i.to_le_bytes());
            let key_address = Address::from_public_key(&pubkey);
            let plain = AddressText::parse(&key_address.to_base58()).unwrap().address();
            let agent = AddressText::parse(&key_address.to_raddress()).unwrap().address();
            assert_eq!(plain, key_address);
            assert_eq!(agent, key_address);
            assert_eq!(plain.as_bytes(), agent.as_bytes());
            assert_eq!(bincode::serialize(&plain).unwrap(), bincode::serialize(&agent).unwrap());
            assert_eq!(HashSet::from([plain, agent]).len(), 1);
        }
    }

    // ── vectors shared with the TypeScript SDK ─────────────────────────────
    //
    // The same strings are in sdk/typescript/src/__tests__/raddress.test.ts, so
    // the SDK's format check and this parser are pinned to the same vectors.
    // The SDK checks only their shape; this parser also verifies the checksum
    // (the RPC refuses a bad one with -32602). Keep the two tables equal.
    //
    // The plain text is base58 of 24 bytes: the 20-byte address and a 4-byte
    // checksum. Each leading zero byte is one `1` and the rest, as a number,
    // takes the fewest base-58 digits, so the text is 24 characters (24 zero
    // bytes) to 33 (58^32 < 2^192 <= 58^33), and under 32 only with two or more
    // leading zero bytes.

    /// Valid addresses of each length: Address::ZERO (26 characters); the
    /// address of the key whose first 8 bytes are 345842 little-endian and the
    /// rest zero (two leading zero bytes, 31); two allocations in
    /// genesis/local_genesis.json (32 and 33).
    const SHARED_VALID: [(&str, usize); 4] = [
        ("111111111111111111112u6Gvy", 26),
        ("11cMv23diqJbvHNnfUXcFZZb6p53x2G", 31),
        ("jVrcPSDyUaqqVJLXbgbYRuhG9bPp4E6j", 32),
        ("ChBEvSC2DKPKr8qFgbSv69Xnm8JNAKdiY", 33),
    ];

    /// The shape of an address (24 bytes) with a wrong checksum: the SDK's
    /// checksum-free format check takes them; this parser refuses them on the
    /// checksum alone. The shortest shape, 24 zero bytes (24 characters), and
    /// the largest 24-byte value (33).
    const SHARED_SHAPE_ONLY: [&str; 2] =
        ["111111111111111111111111", "QLbz7JHiBTspS962RLKV8GndWFwiEaqKL"];

    /// Base58 characters that do not decode to 24 bytes: refused by both, on
    /// length. 23 and 25 zero bytes; 2^192, the smallest 25-byte value (33
    /// characters); the largest 23-byte value with no leading zero byte (32
    /// characters); 33 `z`s (25 bytes).
    const SHARED_WRONG_SHAPE: [&str; 5] = [
        "11111111111111111111111",
        "1111111111111111111111111",
        "QLbz7JHiBTspS962RLKV8GndWFwiEaqKM",
        "6HgC8KRBEhXYbF4riJyJFLSHt32XBnGv",
        "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
    ];

    #[test]
    fn shared_vectors_pin_the_lengths_the_parser_accepts() {
        assert_eq!(SHARED_VALID[0].0, Address::ZERO.to_base58());
        let mut pubkey = [0u8; 32];
        pubkey[..8].copy_from_slice(&345842u64.to_le_bytes());
        assert_eq!(SHARED_VALID[1].0, Address::from_public_key(&pubkey).to_base58());

        for (plain, len) in SHARED_VALID {
            assert_eq!(plain.len(), len, "{plain}");
            let a = Address::from_base58(plain).unwrap();
            assert_eq!(a.to_base58(), plain);
            assert_eq!(AddressText::parse(plain).unwrap(), AddressText::Human(a));
            assert_eq!(AddressText::parse(&format!("r0{plain}")).unwrap(), AddressText::Agent(a));
            assert_eq!(AddressText::parse_or_hex(&format!("r0{plain}")).unwrap(), AddressText::Agent(a));
        }
        for s in SHARED_SHAPE_ONLY {
            assert_eq!(bs58::decode(s).into_vec().unwrap().len(), 24, "{s}");
            assert!(matches!(Address::from_base58(s), Err(PrimitiveError::InvalidChecksum)), "{s}");
            assert!(
                matches!(AddressText::parse(&format!("r0{s}")), Err(PrimitiveError::InvalidChecksum)),
                "{s}"
            );
        }
        for s in SHARED_WRONG_SHAPE {
            assert!(
                matches!(
                    Address::from_base58(s),
                    Err(PrimitiveError::InvalidLength { expected: 24, got }) if got != 24
                ),
                "{s}"
            );
            assert!(AddressText::parse(&format!("r0{s}")).is_err(), "{s}");
        }
    }
}
