//! Emit the normative B0-PRE protocol artifact `b0-pre-protocol-v1.json`.
//!
//! The artifact is assembled purely from the crate's frozen definitions and is
//! `not_finalizable` (every implementation-produced field is absent). Committed
//! as pretty JSON for review; the hash preimage canonicalizes it separately.

use std::fs;
use std::path::Path;

use b0_pre_validator::protocol::B0PreProtocolV1;

fn main() {
    let p = B0PreProtocolV1::frozen();
    assert!(
        p.semantic_violations().is_empty(),
        "frozen artifact has semantic violations: {:?}",
        p.semantic_violations()
    );
    assert!(
        !p.is_finalizable(),
        "frozen artifact must be not_finalizable"
    );

    let json = serde_json::to_string_pretty(&p).expect("serialize");
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/b0-pre/protocol");
    fs::create_dir_all(&dir).expect("mkdir");
    fs::write(dir.join("b0-pre-protocol-v1.json"), format!("{json}\n")).expect("write");

    eprintln!(
        "wrote b0-pre-protocol-v1.json ({} bytes); finalizable={}; blocked_on={:?}",
        json.len() + 1,
        p.is_finalizable(),
        p.finalization.blocked_on
    );
}
