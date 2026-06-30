//! Issue #25, Set 3: deterministic contract-state-diff digest + ordering.

use sumchain_storage::{contract_cf_kind, ContractMutation, ContractStateDiff, CONTRACT_STATE_DIFF_DOMAIN};

fn rec(cf_kind: u8, key: &[u8], old: Option<&[u8]>, new: Option<&[u8]>) -> ContractMutation {
    ContractMutation {
        cf_kind,
        key: key.to_vec(),
        old: old.map(|v| v.to_vec()),
        new: new.map(|v| v.to_vec()),
    }
}

#[test]
fn empty_diff_hashes_to_domain_only() {
    let d = ContractStateDiff::new();
    assert_eq!(d.digest(), *blake3::hash(CONTRACT_STATE_DIFF_DOMAIN).as_bytes());
}

#[test]
fn digest_changes_with_contents() {
    let empty = ContractStateDiff::new().digest();
    let mut d = ContractStateDiff::new();
    d.push(rec(contract_cf_kind::STORAGE, b"a:k", None, Some(b"v")));
    assert_ne!(d.digest(), empty, "non-empty diff must differ from empty");

    // A write vs a delete of the same key must differ.
    let mut del = ContractStateDiff::new();
    del.push(rec(contract_cf_kind::STORAGE, b"a:k", Some(b"v"), None));
    assert_ne!(d.digest(), del.digest(), "write and delete must differ");

    // Different new value must differ.
    let mut d2 = ContractStateDiff::new();
    d2.push(rec(contract_cf_kind::STORAGE, b"a:k", None, Some(b"w")));
    assert_ne!(d.digest(), d2.digest());
}

#[test]
fn ordering_is_deterministic_after_sort() {
    let r1 = rec(contract_cf_kind::STORAGE, b"a:k1", None, Some(b"1"));
    let r2 = rec(contract_cf_kind::CODE, b"addr", None, Some(b"code"));
    let r3 = rec(contract_cf_kind::STORAGE, b"a:k2", None, Some(b"2"));

    let mut a = ContractStateDiff::new();
    a.push(r1.clone());
    a.push(r2.clone());
    a.push(r3.clone());
    a.sort();

    let mut b = ContractStateDiff::new();
    b.push(r3);
    b.push(r1);
    b.push(r2);
    b.sort();

    // Same records, different insertion order -> identical digest after sort.
    assert_eq!(a.digest(), b.digest());
    // Sorted by (cf_kind, key): STORAGE(0) a:k1, a:k2, then CODE(1) addr.
    assert_eq!(a.records[0].key, b"a:k1");
    assert_eq!(a.records[1].key, b"a:k2");
    assert_eq!(a.records[2].cf_kind, contract_cf_kind::CODE);
}

#[test]
fn cf_name_maps_kinds() {
    assert_eq!(ContractStateDiff::cf_name(contract_cf_kind::STORAGE), Some("contract_storage"));
    assert_eq!(ContractStateDiff::cf_name(contract_cf_kind::CODE), Some("contract_code"));
    assert_eq!(ContractStateDiff::cf_name(contract_cf_kind::METADATA), Some("contract_metadata"));
    assert_eq!(ContractStateDiff::cf_name(99), None);
}
