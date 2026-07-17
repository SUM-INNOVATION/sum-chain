//! SNIP Merkle over 1 MiB chunks (plan §8).
//!
//! * `leaf   = BLAKE3(chunk)`
//! * `parent = BLAKE3(left ‖ right)`
//! * odd level → duplicate the last node
//! * single leaf → root is that leaf
//! * empty object → `chunk_count = 0`, root `[0; 32]`
//! * `chunk_count = ceil(byte_len / CHUNK)`
//!
//! The classic 3-leaf-vs-duplicated-4th ambiguity is *not* resolved by the root
//! (both shapes hash to the same root); it is closed one layer up, because
//! `ObjectCommitmentV1` binds `byte_len` and `chunk_count`, so the real leaf
//! count is authenticated independently of tree shape.

pub const CHUNK: usize = 1_048_576;

/// `ceil(byte_len / CHUNK)`; zero for the empty object.
pub fn chunk_count(byte_len: u64) -> u32 {
    if byte_len == 0 {
        return 0;
    }
    let cc = byte_len.div_ceil(CHUNK as u64);
    // Objects in B0-PRE are kilobytes; a count beyond u32 cannot arise from a
    // valid object and is rejected as a length violation upstream.
    debug_assert!(cc <= u32::MAX as u64);
    cc as u32
}

fn leaf(chunk: &[u8]) -> [u8; 32] {
    blake3::hash(chunk).into()
}

fn parent(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(l);
    h.update(r);
    h.finalize().into()
}

/// Reduce a level of leaves to a single root, duplicating the last node on odd
/// levels. Exposed so the tree-shape logic can be tested with synthetic leaves.
pub fn merkle_root_from_leaves(leaves: &[[u8; 32]]) -> [u8; 32] {
    match leaves.len() {
        0 => [0u8; 32],
        1 => leaves[0],
        _ => {
            let mut level = leaves.to_vec();
            while level.len() > 1 {
                if level.len() % 2 == 1 {
                    let last = *level.last().unwrap();
                    level.push(last);
                }
                let mut next = Vec::with_capacity(level.len() / 2);
                let mut i = 0;
                while i < level.len() {
                    next.push(parent(&level[i], &level[i + 1]));
                    i += 2;
                }
                level = next;
            }
            level[0]
        }
    }
}

/// Chunk `data` into 1 MiB leaves and reduce to a root.
pub fn merkle_root(data: &[u8]) -> [u8; 32] {
    if data.is_empty() {
        return [0u8; 32];
    }
    let leaves: Vec<[u8; 32]> = data.chunks(CHUNK).map(leaf).collect();
    merkle_root_from_leaves(&leaves)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_object_is_zero_root_and_zero_count() {
        assert_eq!(merkle_root(&[]), [0u8; 32]);
        assert_eq!(chunk_count(0), 0);
    }

    #[test]
    fn single_leaf_root_is_the_leaf() {
        let data = b"hello world";
        assert_eq!(merkle_root(data), <[u8; 32]>::from(blake3::hash(data)));
        assert_eq!(chunk_count(data.len() as u64), 1);
        // exactly one full chunk is still a single leaf
        assert_eq!(chunk_count(CHUNK as u64), 1);
    }

    #[test]
    fn chunk_boundaries() {
        assert_eq!(chunk_count(CHUNK as u64), 1);
        assert_eq!(chunk_count(CHUNK as u64 + 1), 2);
        assert_eq!(chunk_count(2 * CHUNK as u64), 2);
        assert_eq!(chunk_count(2 * CHUNK as u64 + 1), 3);
    }

    #[test]
    fn final_chunk_uses_remainder_length_not_padding() {
        let mut data = vec![0xABu8; CHUNK + 5];
        // make the two chunks distinguishable
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        let c0 = leaf(&data[..CHUNK]);
        let c1 = leaf(&data[CHUNK..]); // exactly 5 bytes, not padded
        assert_eq!(data[CHUNK..].len(), 5);
        assert_eq!(merkle_root(&data), parent(&c0, &c1));
        assert_eq!(chunk_count(data.len() as u64), 2);
    }

    #[test]
    fn odd_level_duplicates_last() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let c = [3u8; 32];
        let p1 = parent(&a, &b);
        let p2 = parent(&c, &c); // last duplicated
        let expected = parent(&p1, &p2);
        assert_eq!(merkle_root_from_leaves(&[a, b, c]), expected);
    }

    #[test]
    fn three_leaves_and_duplicated_fourth_share_a_root() {
        // The ambiguity: identical roots. It is closed by ObjectCommitmentV1
        // binding chunk_count (see schema::object tests), not by the root.
        let a = [1u8; 32];
        let b = [2u8; 32];
        let c = [3u8; 32];
        assert_eq!(
            merkle_root_from_leaves(&[a, b, c]),
            merkle_root_from_leaves(&[a, b, c, c])
        );
    }
}
