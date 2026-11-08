//! Swarm roster display (#309 item 3): print the agent text form (`r0`) for the
//! accounts on a configured roster, and the plain base58 form for every other
//! account.
//!
//! This is presentation only. `r0` is a text form of the same 20-byte address;
//! it identifies nothing and grants nothing, and no permission, signature, fee
//! or account rule reads it (see `AddressText`). Being on the roster changes how
//! an address is printed here, nothing else.
//!
//! The roster is a file given with `--swarm-roster`: one entry per line (or
//! several, separated by commas or whitespace), each in the plain, `r0` or hex
//! form; `#` starts a comment. Until the chain has a swarm registry, this
//! configured list is the roster's only source.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::OnceLock;

use sumchain_primitives::address::AddressText;
use sumchain_primitives::Address;

/// A set of roster member addresses.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Roster {
    members: BTreeSet<Address>,
}

impl Roster {
    /// Parse a roster. An entry that is not an address is an error naming its
    /// line, so a typo cannot silently leave a member out.
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut members = BTreeSet::new();
        for (n, line) in text.lines().enumerate() {
            let line = line.split('#').next().unwrap_or("");
            for entry in line
                .split(|c: char| c == ',' || c.is_whitespace())
                .filter(|e| !e.is_empty())
            {
                let text = AddressText::parse_or_hex(entry).map_err(|e| {
                    format!(
                        "swarm roster line {}: '{}' is not an address ({})",
                        n + 1,
                        entry,
                        e
                    )
                })?;
                members.insert(text.address());
            }
        }
        Ok(Roster { members })
    }

    /// Read and parse a roster file.
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read swarm roster {}: {}", path.display(), e))?;
        Self::parse(&text)
    }

    pub fn len(&self) -> usize {
        self.members.len()
    }

    pub fn contains(&self, address: &Address) -> bool {
        self.members.contains(address)
    }

    /// The text to print for `address`: `r0…` for a member, plain base58 otherwise.
    pub fn display(&self, address: &Address) -> String {
        if self.contains(address) {
            address.to_raddress()
        } else {
            address.to_base58()
        }
    }

    /// The text to print for an address held as text (as typed, or as an RPC
    /// returned it). A member's address is printed in the `r0` form whatever
    /// form it came in; any other text, including text that is not an address,
    /// is returned unchanged.
    pub fn display_text(&self, text: &str) -> String {
        match AddressText::parse_or_hex(text) {
            Ok(t) if self.contains(&t.address()) => t.address().to_raddress(),
            _ => text.to_string(),
        }
    }
}

static ROSTER: OnceLock<Roster> = OnceLock::new();

/// Install the process-wide roster (once, at startup). Without it every
/// address prints in the plain form.
pub fn init(roster: Roster) {
    let _ = ROSTER.set(roster);
}

fn current() -> &'static Roster {
    static EMPTY: OnceLock<Roster> = OnceLock::new();
    ROSTER
        .get()
        .unwrap_or_else(|| EMPTY.get_or_init(Roster::default))
}

/// [`Roster::display`] with the installed roster.
pub fn show(address: &Address) -> String {
    current().display(address)
}

/// [`Roster::display_text`] with the installed roster.
pub fn show_text(text: &str) -> String {
    current().display_text(text)
}

/// Parse an address argument in the plain, `r0` or hex form. For text without
/// the `r0` prefix the result and the error are those of
/// `Address::from_base58(s).or_else(|_| Address::from_hex(s))`, which this
/// replaces, so an `r0` address the wallet printed can be pasted back.
pub fn parse_address(s: &str) -> sumchain_primitives::Result<Address> {
    AddressText::parse_or_hex(s).map(AddressText::address)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(n: u8) -> Address {
        let mut b = [0u8; 20];
        b[0] = 0x11;
        b[19] = n;
        Address::new(b)
    }

    #[test]
    fn members_print_r0_and_others_plain() {
        let (a, b, c) = (addr(1), addr(2), addr(3));
        let text = format!(
            "# swarm A\n{}\n{} , 0x{}  # hex\n",
            a.to_base58(),
            b.to_raddress(),
            hex::encode(c.as_bytes())
        );
        let r = Roster::parse(&text).unwrap();
        assert_eq!(r.len(), 3);
        for m in [a, b, c] {
            assert_eq!(r.display(&m), format!("r0{}", m.to_base58()));
        }
        let other = addr(4);
        assert_eq!(r.display(&other), other.to_base58());
    }

    #[test]
    fn duplicates_and_forms_collapse_to_one_member() {
        let a = addr(7);
        let r = Roster::parse(&format!(
            "{} {} 0x{}",
            a.to_base58(),
            a.to_raddress(),
            hex::encode(a.as_bytes())
        ))
        .unwrap();
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn a_bad_entry_is_an_error_naming_its_line() {
        let a = addr(1);
        let e = Roster::parse(&format!("{}\nnot-an-address\n", a.to_base58())).unwrap_err();
        assert!(e.contains("line 2") && e.contains("not-an-address"), "{e}");
        // A damaged checksum is not silently accepted either.
        let mut bad = a.to_base58();
        let last = bad.pop().unwrap();
        bad.push(if last == '2' { '3' } else { '2' });
        assert!(Roster::parse(&bad).is_err());
    }

    #[test]
    fn empty_and_comment_only_rosters_are_empty() {
        assert_eq!(Roster::parse("").unwrap().len(), 0);
        assert_eq!(Roster::parse("# nothing yet\n\n").unwrap().len(), 0);
        let a = addr(1);
        assert_eq!(Roster::default().display(&a), a.to_base58());
    }

    #[test]
    fn display_text_rewrites_members_only_and_never_alters_other_text() {
        let (a, other) = (addr(1), addr(2));
        let r = Roster::parse(&a.to_base58()).unwrap();
        assert_eq!(r.display_text(&a.to_base58()), a.to_raddress());
        assert_eq!(r.display_text(&a.to_raddress()), a.to_raddress());
        assert_eq!(
            r.display_text(&format!("0x{}", hex::encode(a.as_bytes()))),
            a.to_raddress()
        );
        assert_eq!(r.display_text(&other.to_base58()), other.to_base58());
        let hex_other = format!("0x{}", hex::encode(other.as_bytes()));
        assert_eq!(r.display_text(&hex_other), hex_other);
        for junk in ["", "validator-1", "r0", "0x", "r0not-base58"] {
            assert_eq!(r.display_text(junk), junk);
        }
    }

    #[test]
    fn parse_address_accepts_r0_and_matches_the_old_parser_otherwise() {
        let a = addr(9);
        assert_eq!(parse_address(&a.to_raddress()).unwrap(), a);
        let hex = format!("0x{}", hex::encode(a.as_bytes()));
        for s in [
            a.to_base58(),
            hex.clone(),
            hex[2..].to_string(),
            "nonsense".to_string(),
            String::new(),
        ] {
            let old = Address::from_base58(&s).or_else(|_| Address::from_hex(&s));
            match (old, parse_address(&s)) {
                (Ok(x), Ok(y)) => assert_eq!(x, y, "{s}"),
                (Err(x), Err(y)) => assert_eq!(x.to_string(), y.to_string(), "{s}"),
                (x, y) => panic!("{s}: old {x:?}, new {y:?}"),
            }
        }
        // `r0` text is the agent form or an error, never retried as plain or hex.
        assert!(parse_address("r0nonsense").is_err());
    }

    #[test]
    fn printed_addresses_paste_back_as_the_same_account() {
        let (member, other) = (addr(1), addr(2));
        let r = Roster::parse(&member.to_raddress()).unwrap();
        for a in [member, other] {
            assert_eq!(parse_address(&r.display(&a)).unwrap(), a);
            let hex = format!("0x{}", hex::encode(a.as_bytes()));
            assert_eq!(parse_address(&r.display_text(&hex)).unwrap(), a);
        }
    }

    #[test]
    fn the_r0_form_changes_no_signed_byte() {
        // A transfer to an address given in the r0 form is the same transaction, signature and fee as one to the
        // plain form: the form is text only, and the roster is consulted for display alone.
        let keystore = crate::keystore::Keystore::generate("test").unwrap();
        let to = addr(5);
        let plain = crate::tx::sign_transaction(
            &keystore,
            parse_address(&to.to_base58()).unwrap(),
            100,
            10,
            3,
            1,
        )
        .unwrap();
        let agent = crate::tx::sign_transaction(
            &keystore,
            parse_address(&to.to_raddress()).unwrap(),
            100,
            10,
            3,
            1,
        )
        .unwrap();
        assert_eq!(plain.to_hex(), agent.to_hex());
    }
}
