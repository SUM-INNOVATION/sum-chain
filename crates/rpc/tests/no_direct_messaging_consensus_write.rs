//! Static guard (sum-chain #145): production RPC handlers must NEVER write the
//! messaging public-key consensus column family directly. Registration state is
//! block-ordered and may be produced ONLY by consensus execution of a
//! `RegisterPublicKeySponsoredV1` transaction — a node-local RPC write is
//! exactly the divergence that forked validators before this fix.
//!
//! This scans the RPC server source and asserts it contains no `set_public_key`
//! / `delete_public_key` call and no direct reference to the
//! `MESSAGING_PUBLIC_KEYS` column family. Read paths (`get_public_key`,
//! `has_public_key`) are allowed — they never mutate consensus state.

const SERVER_SRC: &str = include_str!("../src/server.rs");

#[test]
fn production_rpc_has_no_direct_messaging_pubkey_write() {
    // Assemble the forbidden needles from fragments so this guard file never
    // self-matches if it is itself ever swept by a similar scan.
    let write_call = ["set", "_public_key"].concat();
    let delete_call = ["delete", "_public_key"].concat();
    let cf_name = ["MESSAGING", "_PUBLIC_KEYS"].concat();

    assert!(
        !SERVER_SRC.contains(&write_call),
        "production RPC (crates/rpc/src/server.rs) must not call `set_public_key` — \
         messaging registration must flow through consensus execution, not a \
         node-local RPC write (issue #145)."
    );
    assert!(
        !SERVER_SRC.contains(&delete_call),
        "production RPC must not call `delete_public_key`."
    );
    assert!(
        !SERVER_SRC.contains(&cf_name),
        "production RPC must not touch the MESSAGING_PUBLIC_KEYS column family directly."
    );
}
