//! Cross-implementation golden for the effective-cpuset probe-chain content address.
//!
//! The authoritative producer (`b0-pre-validator`, `schema::provenance::cpuset_probe_chain_hash`)
//! and this INDEPENDENT re-derivation must agree byte-for-byte on the address of a fixed retained
//! chain. Both pin the SAME value here and in the validator's
//! `provenance::tests::cpuset_chain_hash_is_stable_cross_impl_golden`, so the two implementations of
//! the canonical rule cannot silently diverge (the same guarantee the DVFS-evidence cross-impl golden
//! provides).

/// Independent re-derivation of the canonical observation string (state / raw / file_type /
/// is_symlink / dev / inode / size / mtime_secs / mtime_nanos / read_error_class), with `_` for an
/// absent optional field — exactly the rule the reference implements.
#[allow(clippy::too_many_arguments)]
fn obs_canon(
    state: u8,
    raw: &str,
    file_type: &str,
    is_symlink: bool,
    dev: Option<u64>,
    inode: Option<u64>,
    size: Option<u64>,
    mtime_secs: Option<i64>,
    mtime_nanos: Option<i64>,
    read_error_class: Option<&str>,
) -> String {
    let ou = |x: Option<u64>| x.map(|v| v.to_string()).unwrap_or_else(|| "_".into());
    let oi = |x: Option<i64>| x.map(|v| v.to_string()).unwrap_or_else(|| "_".into());
    format!(
        "{}/{}/{}/{}/{}/{}/{}/{}/{}/{}",
        state,
        raw,
        file_type,
        is_symlink as u8,
        ou(dev),
        ou(inode),
        ou(size),
        oi(mtime_secs),
        oi(mtime_nanos),
        read_error_class.unwrap_or("_")
    )
}

#[test]
fn cpuset_probe_chain_hash_matches_reference_golden() {
    // The SAME fixed chain the validator pins: leaf (order 0) absent, ancestor (order 1) nonempty
    // "0-1"; dev=1, inode=2, size=raw.len(), mtime 100/200.
    let leaf = obs_canon(
        0,
        "",
        "absent",
        false,
        Some(1),
        Some(2),
        Some(0),
        Some(100),
        Some(200),
        None,
    );
    let anc = obs_canon(
        2,
        "0-1",
        "regular",
        false,
        Some(1),
        Some(2),
        Some(3),
        Some(100),
        Some(200),
        None,
    );
    let mut canonical = String::from("b0-final-cpuset-probe-chain/v1");
    canonical.push_str(&format!("|entry:0:/b0.slice/measure:[{leaf}]:[{leaf}]"));
    canonical.push_str(&format!("|entry:1:/b0.slice:[{anc}]:[{anc}]"));
    let mut h = blake3::Hasher::new();
    h.update(b"b0-final-cpuset-probe-chain-hash/v1\0");
    h.update(canonical.as_bytes());
    let mut hex = String::new();
    for b in h.finalize().as_bytes() {
        hex.push_str(&format!("{b:02x}"));
    }
    assert_eq!(
        hex, "3b01b8cfa7bfc1cfee72837366799bb7873de915b7a0a6ba38312b3322dae1aa",
        "independent cpuset-chain address diverged from the reference golden"
    );
}
