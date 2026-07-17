//! BLAKE3 helpers for the domain-prefixed hash rules (plan §17).

/// `BLAKE3(prefix ‖ data)` — the shape of every domain-prefixed hash.
pub fn prefixed(prefix: &[u8], data: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(prefix);
    h.update(data);
    h.finalize().into()
}

/// `BLAKE3(data)` — used where the bytes self-domain via a leading tag
/// (e.g. `computation_statement_hash` over the 996-byte statement).
pub fn plain(data: &[u8]) -> [u8; 32] {
    blake3::hash(data).into()
}
