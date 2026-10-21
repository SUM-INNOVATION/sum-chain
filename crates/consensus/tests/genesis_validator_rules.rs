//! Genesis validation's validator-count bound (VS-6(a), ratified 2026-10-21)
//! is the ConsensusConfig codec's own bound on field 0x0003. The genesis crate
//! cannot name the codec, so the two are pinned equal here.

use sumchain_consensus::consensus_config::codec::{
    MAX_ENCODABLE_VALIDATORS, MAX_FIELD_VALUE_BYTES,
};
use sumchain_genesis::MAX_GENESIS_VALIDATORS;

#[test]
fn the_genesis_bound_is_the_encodable_bound() {
    assert_eq!(MAX_GENESIS_VALIDATORS, MAX_ENCODABLE_VALIDATORS);
    assert_eq!(
        4 + 36 * MAX_GENESIS_VALIDATORS,
        MAX_FIELD_VALUE_BYTES as usize
    );
}
