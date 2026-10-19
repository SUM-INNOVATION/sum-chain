//! The six "custodial signing" methods: RPC calls that take the caller's raw
//! private key and sign on the server.
//!
//! - `docclass_registerAcademicIssuer`, `docclass_issueAcademicCredential`,
//!   `docclass_revokeAcademicCredential`;
//! - `employment_registerIssuer`, `employment_createCredential`,
//!   `employment_revokeCredential`.
//!
//! A server should never receive a private key. These methods are therefore
//! **off by default**: a node serves them only when its operator opts in, per
//! family, with `[rpc] unsafe_custodial_docclass_methods` or
//! `[rpc] unsafe_custodial_employment_methods`. Off, each answers with a fixed
//! error ([`RpcError::MethodDisabled`], `-32005`) before it reads any
//! parameter, and the error names the client-side replacement where one
//! exists:
//!
//! - DocClass: `docclass_buildTransaction` (takes an address, never a key),
//!   local signing with `sumchain docclass`, then `send_raw_transaction`;
//! - employment: no client-side replacement yet; the operator flag is the
//!   compatibility path until one exists.
//!
//! On, the node logs a deprecation warning at startup and on every call. The
//! warning names the method and nothing from the request.
//!
//! The key a request carries is held in [`CustodialKeyHex`]: its `Debug`
//! output is redacted, its memory is zeroized when it is dropped, and a
//! malformed key is refused with a fixed message that never repeats a
//! character or a position from it. That covers this crate's copies only; the
//! JSON-RPC transport's own request buffers are outside it, which is one more
//! reason the methods are off.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

use crate::RpcError;

/// Error returned by a DocClass custodial method on a node that has not opted
/// in. Fixed text: it never includes anything from the request.
pub const DOCCLASS_CUSTODIAL_DISABLED: &str = "custodial signing is disabled on this node: \
     the server will not take a private key. Build the transaction with \
     docclass_buildTransaction (sender address, no key), sign it locally \
     (sumchain docclass), and submit it with send_raw_transaction";

/// Error returned by an employment custodial method on a node that has not
/// opted in. Fixed text: it never includes anything from the request.
pub const EMPLOYMENT_CUSTODIAL_DISABLED: &str = "custodial signing is disabled on this node: \
     the server will not take a private key. Employment operations have no \
     client-side builder yet; a node operator who must keep serving existing \
     clients can re-enable them with [rpc] unsafe_custodial_employment_methods";

/// Refusal for a key that is not hex (or has an odd number of digits).
pub const CUSTODIAL_KEY_NOT_HEX: &str = "Invalid private key: expected 32 bytes as hex";

/// Refusal for hex that does not decode to exactly 32 bytes. The text is the
/// one these methods have always returned for a wrong length.
pub const CUSTODIAL_KEY_WRONG_LENGTH: &str = "Private key must be 32 bytes";

/// The two custodial method families, enabled separately.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustodialFamily {
    DocClass,
    Employment,
}

/// Which custodial families this node serves. Both off by default.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CustodialSigningMethods {
    /// Serve the three DocClass custodial methods.
    pub docclass: bool,
    /// Serve the three employment custodial methods.
    pub employment: bool,
}

impl CustodialSigningMethods {
    /// Whether this node serves `family`.
    pub fn enabled(&self, family: CustodialFamily) -> bool {
        match family {
            CustodialFamily::DocClass => self.docclass,
            CustodialFamily::Employment => self.employment,
        }
    }

    /// Admit or refuse one call. Refused: the family's fixed error. Admitted:
    /// a deprecation warning naming the method, and nothing from the request.
    pub(crate) fn admit(
        &self,
        family: CustodialFamily,
        method: &'static str,
    ) -> Result<(), RpcError> {
        if !self.enabled(family) {
            return Err(RpcError::MethodDisabled(
                match family {
                    CustodialFamily::DocClass => DOCCLASS_CUSTODIAL_DISABLED,
                    CustodialFamily::Employment => EMPLOYMENT_CUSTODIAL_DISABLED,
                }
                .to_string(),
            ));
        }
        tracing::warn!(
            method,
            "deprecated custodial signing method called: the request carried a private key; \
             clients should build, sign and submit transactions locally"
        );
        Ok(())
    }
}

/// A private key carried in a custodial request, as hex.
///
/// `Debug` prints `CustodialKeyHex(<redacted>)`; the string is zeroized on
/// drop. Serializing writes the hex back out, which only a client building a
/// request does.
#[derive(Clone)]
pub struct CustodialKeyHex(Zeroizing<String>);

impl CustodialKeyHex {
    pub fn new(hex: impl Into<String>) -> Self {
        Self(Zeroizing::new(hex.into()))
    }
}

impl From<String> for CustodialKeyHex {
    fn from(hex: String) -> Self {
        Self::new(hex)
    }
}

impl From<&str> for CustodialKeyHex {
    fn from(hex: &str) -> Self {
        Self::new(hex)
    }
}

impl fmt::Debug for CustodialKeyHex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CustodialKeyHex(<redacted>)")
    }
}

impl Serialize for CustodialKeyHex {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for CustodialKeyHex {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self::new)
    }
}

/// Why a custodial key was refused. Each has one fixed message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustodialKeyError {
    /// Not hex, or an odd number of digits: [`CUSTODIAL_KEY_NOT_HEX`].
    NotHex,
    /// Hex, but not 32 bytes: [`CUSTODIAL_KEY_WRONG_LENGTH`].
    WrongLength,
}

impl CustodialKeyError {
    pub fn message(self) -> &'static str {
        match self {
            CustodialKeyError::NotHex => CUSTODIAL_KEY_NOT_HEX,
            CustodialKeyError::WrongLength => CUSTODIAL_KEY_WRONG_LENGTH,
        }
    }
}

/// Decode a custodial key into a keypair, through zeroized buffers.
///
/// A `0x` prefix is accepted, as before. Refusals carry a fixed message only.
pub fn custodial_keypair(
    key: &CustodialKeyHex,
) -> Result<sumchain_crypto::KeyPair, CustodialKeyError> {
    let digits = key.0.strip_prefix("0x").unwrap_or(&key.0);
    if digits.len() % 2 != 0 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(CustodialKeyError::NotHex);
    }
    if digits.len() != 64 {
        return Err(CustodialKeyError::WrongLength);
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    hex::decode_to_slice(digits, &mut seed[..]).map_err(|_| CustodialKeyError::NotHex)?;
    Ok(sumchain_crypto::KeyPair::from_bytes(*seed))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthetic: a fixed test seed, never a real key.
    fn synthetic_hex() -> String {
        hex::encode([0x5a; 32])
    }

    #[test]
    fn debug_is_redacted() {
        let k = CustodialKeyHex::new(synthetic_hex());
        let shown = format!("{k:?}");
        assert_eq!(shown, "CustodialKeyHex(<redacted>)");
        assert!(!shown.contains("5a5a"));
    }

    #[test]
    fn a_valid_key_decodes_with_or_without_prefix() {
        let plain = custodial_keypair(&CustodialKeyHex::new(synthetic_hex())).unwrap();
        let prefixed =
            custodial_keypair(&CustodialKeyHex::new(format!("0x{}", synthetic_hex()))).unwrap();
        assert_eq!(plain.address(), prefixed.address());
        assert_eq!(
            plain.address(),
            sumchain_crypto::KeyPair::from_bytes([0x5a; 32]).address()
        );
    }

    #[test]
    fn malformed_keys_get_one_fixed_message_each() {
        let not_hex = [
            "zz".repeat(32),
            format!("{}g", "5a".repeat(31)) + "5",
            "5a".repeat(31) + "5",
            "0x".to_string() + &"q".repeat(64),
        ];
        for k in &not_hex {
            assert_eq!(
                custodial_keypair(&CustodialKeyHex::new(k.clone())).err(),
                Some(CustodialKeyError::NotHex)
            );
        }
        for k in ["5a".repeat(31), "5a".repeat(33), String::new()] {
            assert_eq!(
                custodial_keypair(&CustodialKeyHex::new(k)).err(),
                Some(CustodialKeyError::WrongLength)
            );
        }
        // The messages carry no character or position from any input.
        for m in [CUSTODIAL_KEY_NOT_HEX, CUSTODIAL_KEY_WRONG_LENGTH] {
            assert!(!m.contains('\'') && !m.contains("position") && !m.contains("index"));
        }
    }

    #[test]
    fn serde_round_trips_the_hex() {
        let k = CustodialKeyHex::new(synthetic_hex());
        let json = serde_json::to_string(&k).unwrap();
        let back: CustodialKeyHex = serde_json::from_str(&json).unwrap();
        assert_eq!(
            custodial_keypair(&back).unwrap().address(),
            custodial_keypair(&k).unwrap().address()
        );
    }

    #[test]
    fn both_families_are_off_by_default() {
        let d = CustodialSigningMethods::default();
        assert!(!d.enabled(CustodialFamily::DocClass));
        assert!(!d.enabled(CustodialFamily::Employment));
        match d.admit(
            CustodialFamily::DocClass,
            "docclass_issueAcademicCredential",
        ) {
            Err(RpcError::MethodDisabled(m)) => assert_eq!(m, DOCCLASS_CUSTODIAL_DISABLED),
            other => panic!("expected the fixed refusal, got {other:?}"),
        }
        match d.admit(CustodialFamily::Employment, "employment_createCredential") {
            Err(RpcError::MethodDisabled(m)) => assert_eq!(m, EMPLOYMENT_CUSTODIAL_DISABLED),
            other => panic!("expected the fixed refusal, got {other:?}"),
        }
    }
}
