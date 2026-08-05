//! The committed owner-ratified third-party notice map loads and is structurally valid: unique
//! family ids, non-empty sha-true sorted-unique notices, and no crate covered by two families.
//! (Ratification of the texts themselves is an owner decision; this only guards structural drift.)

use b0_pre_validator::venue::third_party_notices::RatifiedNoticeMap;

const MAP: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../b0-pre-candidates/policy/third-party-notice-map.json"
));

#[test]
fn committed_notice_map_loads_and_validates() {
    let m = RatifiedNoticeMap::load(MAP)
        .expect("committed third-party notice map must load + structurally validate");
    assert!(!m.families.is_empty(), "map has no families");
    assert!(
        !m.policy_version.trim().is_empty(),
        "map has empty policy_version"
    );
}
