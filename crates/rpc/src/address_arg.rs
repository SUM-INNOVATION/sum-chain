//! Address arguments (sum-chain #309).
//!
//! Every method that takes an address reads it here. Each also accepts the
//! agent text form, `r0` followed by the plain base58 address
//! ([`AddressText`]), as the same address. Which form was written is not kept
//! and changes nothing a method does: no method refuses either form, and every
//! address the RPC returns is printed in the plain base58 form.

use sumchain_primitives::Address;
use sumchain_wire::address::AddressText;

/// An address argument of a method that takes base58 or hex: the plain base58
/// form, the `r0` agent form, or hex with or without `0x`.
///
/// An argument that starts with `r0` is the agent form or an error, never
/// retried as hex. For any other argument the result and the error are those
/// of the base58-then-hex rule this replaces.
pub fn parse_address_arg(s: &str) -> sumchain_wire::Result<Address> {
    AddressText::parse_or_hex(s).map(AddressText::address)
}

/// An address argument of a method that takes base58 only: the plain base58
/// form or the `r0` agent form. Hex stays refused here, as before.
pub fn parse_base58_address_arg(s: &str) -> sumchain_wire::Result<Address> {
    AddressText::parse(s).map(AddressText::address)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr() -> Address {
        Address::from_public_key(&[0x30; 32])
    }

    #[test]
    fn every_form_names_the_same_address() {
        let a = addr();
        for s in [a.to_base58(), a.to_raddress(), a.to_hex(), a.to_hex()[2..].to_string()] {
            assert_eq!(parse_address_arg(&s).unwrap(), a, "{s}");
        }
        for s in [a.to_base58(), a.to_raddress()] {
            assert_eq!(parse_base58_address_arg(&s).unwrap(), a, "{s}");
        }
    }

    #[test]
    fn genesis_addresses_of_32_and_33_characters_take_both_forms() {
        // Allocations in genesis/local_genesis.json.
        for plain in ["jVrcPSDyUaqqVJLXbgbYRuhG9bPp4E6j", "ChBEvSC2DKPKr8qFgbSv69Xnm8JNAKdiY"] {
            let a = parse_address_arg(plain).unwrap();
            assert_eq!(a.to_base58(), plain);
            assert_eq!(a.to_raddress(), format!("r0{plain}"));
            assert_eq!(parse_address_arg(&a.to_raddress()).unwrap(), a);
            assert_eq!(parse_base58_address_arg(&a.to_raddress()).unwrap(), a);
        }
    }

    #[test]
    fn base58_only_methods_still_refuse_hex() {
        let a = addr();
        assert!(parse_base58_address_arg(&a.to_hex()).is_err());
        assert!(parse_base58_address_arg(&a.to_hex()[2..]).is_err());
    }

    #[test]
    fn r0_is_never_read_as_hex() {
        let a = addr();
        for s in [
            format!("r0{}", a.to_hex()),
            format!("r0{}", &a.to_hex()[2..]),
            "r0".to_string(),
            format!("r0{}", &a.to_base58()[1..]),
        ] {
            assert!(parse_address_arg(&s).is_err(), "{s}");
            assert!(parse_base58_address_arg(&s).is_err(), "{s}");
        }
    }

    #[test]
    fn errors_off_the_prefix_are_unchanged() {
        let old_or_hex = |s: &str| Address::from_base58(s).or_else(|_| Address::from_hex(s));
        for s in ["", "notanaddress", "0x12", "0xzz", "SUM1abc"] {
            assert_eq!(
                parse_address_arg(s).unwrap_err().to_string(),
                old_or_hex(s).unwrap_err().to_string(),
                "{s}"
            );
            assert_eq!(
                parse_base58_address_arg(s).unwrap_err().to_string(),
                Address::from_base58(s).unwrap_err().to_string(),
                "{s}"
            );
        }
    }
}
