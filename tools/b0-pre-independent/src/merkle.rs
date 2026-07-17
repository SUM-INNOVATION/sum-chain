//! Independent Merkle implementation (recursive; distinct code from the
//! reference's iterative version). Same rules: 1 MiB chunks, BLAKE3 leaves,
//! BLAKE3(l‖r) parents, odd levels pair the last node with itself, single leaf
//! is the root, empty is `[0; 32]`.

pub const CHUNK: usize = 1 << 20;

fn leaf(chunk: &[u8]) -> [u8; 32] {
    blake3::hash(chunk).into()
}

fn node(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(l);
    h.update(r);
    h.finalize().into()
}

fn reduce(level: &[[u8; 32]]) -> [u8; 32] {
    if level.len() == 1 {
        return level[0];
    }
    let mut next = Vec::with_capacity(level.len().div_ceil(2));
    let mut i = 0;
    while i < level.len() {
        let l = level[i];
        // odd tail pairs with itself (duplicate-last)
        let r = if i + 1 < level.len() {
            level[i + 1]
        } else {
            level[i]
        };
        next.push(node(&l, &r));
        i += 2;
    }
    reduce(&next)
}

pub fn root(data: &[u8]) -> [u8; 32] {
    if data.is_empty() {
        return [0u8; 32];
    }
    let leaves: Vec<[u8; 32]> = data.chunks(CHUNK).map(leaf).collect();
    reduce(&leaves)
}

pub fn chunk_count(byte_len: u64) -> u32 {
    if byte_len == 0 {
        0
    } else {
        byte_len.div_ceil(CHUNK as u64) as u32
    }
}
