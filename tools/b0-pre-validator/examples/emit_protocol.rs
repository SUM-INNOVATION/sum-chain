//! Emit the normative B0-PRE protocol artifact `b0-pre-protocol-v1.json`.
//!
//! The committed artifact is the owner-RATIFIED, FINALIZED form
//! ([`B0PreProtocolV1::ratified_finalized`]): the `frozen()` preregistration
//! template with its three Stage-1 categories resolved through the production
//! Stage-1 ingestion transition. It is `finalizable`, so `protocol_hash()` of it
//! is the real `b0_pre_spec_hash`. Committed as pretty JSON for review; the hash
//! preimage canonicalizes it separately.

use std::fs;
use std::path::Path;

use b0_pre_validator::protocol::B0PreProtocolV1;

fn main() {
    let p = B0PreProtocolV1::ratified_finalized();
    assert!(
        p.semantic_violations().is_empty(),
        "ratified artifact has semantic violations: {:?}",
        p.semantic_violations()
    );
    assert!(p.is_finalizable(), "ratified artifact must be finalizable");

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
