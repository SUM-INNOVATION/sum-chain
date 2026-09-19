//! Driving consensus from the RPC server must be a COMPILE error, not a
//! convention.
//!
//! # The capability that was removed
//!
//! `ConsensusWrapper::as_consensus_engine` used to hand `RpcServer` the SAME
//! `Arc<PoAEngine>` the node event loop holds, upcast to
//! `Arc<dyn ConsensusEngine>`. `import_block` is a method on that trait, and
//! `PoAEngine::import_block` is the only caller of `do_import_block` — one
//! function that validates a block, classifies it against
//! `LongestChainForkChoice::should_switch` and then extends, side-branches or
//! REORGS. So the RPC server held a live, callable handle into proposal
//! acceptance and fork choice, reachable from an HTTP request, with no `PeerId`
//! anywhere near it for `Node::admit_peer_block`'s participation check to
//! judge. Not a sixth route through that boundary — a route around it.
//!
//! No RPC method called it. That was the result of a text search, not a
//! property of the design, and a boundary a future handler can bypass by
//! calling a method it was handed is not a boundary.
//!
//! The handle is now `Arc<dyn ConsensusQuery>` (`crates/consensus/src/engine.rs`),
//! whose members are exactly the eight reads `crates/rpc/src/server.rs`
//! performs. The mistake no longer has a representation.
//!
//! # What this file establishes, precisely
//!
//! Each probe below is a standalone program compiled by `rustc` against the
//! workspace's own `sumchain_consensus` rlib — the real trait, not a model of
//! it. A probe "passes" when rustc REJECTS it.
//!
//! * PROVES: `dyn ConsensusQuery` has no `import_block`, `propose_block`,
//!   `start`, `stop`, `init_genesis`, `subscribe`, `is_proposer`,
//!   `get_block_by_height` or `load_chain`, and cannot be converted back into
//!   a `dyn ConsensusEngine` — there is no `Any` supertrait, so the narrowing
//!   is one-way and final.
//! * PROVES, via [`ENGINE_CONTROL`]: the rejections are about the NARROWED
//!   type, not about the capability having been deleted from the codebase.
//!   `dyn ConsensusEngine` still compiles `import_block`. Without this control
//!   every negative below would pass in a world where `import_block` was simply
//!   renamed, which would prove nothing about the RPC surface.
//! * PROVES, via [`QUERY_CONTROL`] and `the_probe_harness_accepts_valid_code`:
//!   the harness can compile valid code, so its rejections are rejections and
//!   not toolchain breakage.
//!
//! * Does NOT prove the RPC server's field has this type. That is
//!   `consensus_handle_is_query_only` in `crates/rpc/src/server.rs`, which
//!   binds `&RpcServer.consensus` at `&Arc<dyn ConsensusQuery>` — an unsizing
//!   coercion cannot reach inside a `&Arc<_>`, so widening the field back stops
//!   the crate's tests compiling. The two files are the chain: the handle has
//!   this type, and this type cannot drive consensus.
//! * Does NOT prove an RPC handler cannot construct its OWN `PoAEngine` and
//!   call `import_block` on that. Nothing about a handle's type can. That
//!   residual route is why the source scan in
//!   `crates/node/tests/consensus_participation_guard.rs` is kept rather than
//!   retired.

/// A valid program against the narrowed handle. If this stops compiling the
/// harness is broken and every rejection below would pass for the wrong reason.
const QUERY_CONTROL: &str = "fn probe(q: &dyn sumchain_consensus::ConsensusQuery) {\n\
     let _ = q.current_height();\n\
     let _ = q.finality_depth();\n\
     let _ = q.is_finalized(7);\n\
     let _ = q.validators();\n\
     let _ = q.get_proposer(7);\n\
     }";

/// The capability still EXISTS — on the full engine trait, where the node event
/// loop uses it. Every rejection below is therefore a statement about
/// `dyn ConsensusQuery`, not about `import_block` having disappeared.
const ENGINE_CONTROL: &str = "fn probe(e: &dyn sumchain_consensus::ConsensusEngine) {\n\
     let _ = e.import_block(unimplemented!());\n\
     }";

/// The directory holding this workspace's compiled rlibs.
///
/// Derived from THIS TEST BINARY's own path, not from the manifest directory:
/// an integration test runs from `<target>/debug/deps/` whatever
/// `CARGO_TARGET_DIR` is set to, and this repository routinely builds into an
/// isolated target directory.
fn deps_dir() -> std::path::PathBuf {
    let exe = std::env::current_exe().expect("test binary path");
    exe.parent()
        .expect("test binary has a parent directory")
        .to_path_buf()
}

/// The rlib to compile probes against.
///
/// Chosen by trying candidates newest-first until one compiles
/// [`QUERY_CONTROL`], NOT simply by taking the newest. `target/debug/deps`
/// accumulates rlibs, and a stale one built by a different rustc yields
/// `E0514: found crate compiled by an incompatible version of rustc` — which
/// would make every negative test below pass for a reason that has nothing to
/// do with the trait under test.
fn working_rlib() -> String {
    let deps = deps_dir();
    let mut candidates: Vec<(std::time::SystemTime, String)> = Vec::new();
    for e in std::fs::read_dir(&deps).expect("read deps dir") {
        let path = e.expect("entry").path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name.starts_with("libsumchain_consensus-") && name.ends_with(".rlib") {
            let m = path
                .metadata()
                .and_then(|m| m.modified())
                .unwrap_or(std::time::UNIX_EPOCH);
            candidates.push((m, path.to_string_lossy().to_string()));
        }
    }
    candidates.sort_by(|a, b| b.0.cmp(&a.0));
    assert!(
        !candidates.is_empty(),
        "no sumchain_consensus rlib in {}; run `cargo build -p sumchain-consensus` first",
        deps.display()
    );

    for (_, rlib) in &candidates {
        if compile_with(QUERY_CONTROL, rlib).0 {
            return rlib.clone();
        }
    }
    panic!(
        "no rlib in {} could compile the control program; the probe harness \
         cannot distinguish a capability rejection from a toolchain mismatch",
        deps.display()
    );
}

/// Compile `program` against `rlib`. Returns `(succeeded, stderr)`.
fn compile_with(program: &str, rlib: &str) -> (bool, String) {
    let dir = tempfile::tempdir().expect("tempdir");
    let src = dir.path().join("probe.rs");
    let text =
        format!("fn main() {{}}\n#[allow(unused, dead_code, unreachable_code)]\n{program}\n");
    std::fs::write(&src, text).expect("write probe");

    let out = std::process::Command::new("rustc")
        .args(["--edition", "2021", "--crate-type", "bin", "-o"])
        .arg(dir.path().join("probe_bin"))
        .arg(&src)
        .arg("-L")
        .arg(deps_dir())
        .arg("--extern")
        .arg(format!("sumchain_consensus={rlib}"))
        .output()
        .expect("run rustc");

    (
        out.status.success(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

/// Compile a program; return `(it_failed, stderr)`. Failure is the desired
/// outcome for a negative probe.
fn rejected(program: &str) -> (bool, String) {
    let rlib = working_rlib();
    let (ok, stderr) = compile_with(program, &rlib);
    assert!(
        !stderr.contains("E0514"),
        "toolchain mismatch reached a negative probe; working_rlib should have \
         filtered it:\n{stderr}"
    );
    (!ok, stderr)
}

#[test]
fn the_probe_harness_accepts_valid_code() {
    // Guard the guard. If everything failed to compile for an unrelated reason,
    // every rejection below would pass vacuously.
    let rlib = working_rlib();
    let (ok, stderr) = compile_with(QUERY_CONTROL, &rlib);
    assert!(
        ok,
        "the harness cannot compile the eight reads the RPC server performs, so \
         its rejections prove nothing:\n{stderr}"
    );
}

#[test]
fn the_capability_still_exists_on_the_full_engine_trait() {
    // The other half of guarding the guard. A world where `import_block` was
    // renamed or deleted would satisfy every negative probe below while saying
    // nothing whatever about the RPC server's handle.
    let rlib = working_rlib();
    let (ok, stderr) = compile_with(ENGINE_CONTROL, &rlib);
    assert!(
        ok,
        "`dyn ConsensusEngine` no longer compiles `import_block`. The negative \
         probes in this file would then pass for the wrong reason — they assert \
         that the NARROWED handle lacks a capability the full engine has:\n{stderr}"
    );
}

#[test]
fn the_rpc_handle_cannot_accept_a_proposal() {
    let (failed, stderr) = rejected(
        "fn probe(q: &dyn sumchain_consensus::ConsensusQuery) {\n\
         let _ = q.import_block(unimplemented!());\n\
         }",
    );
    assert!(
        failed,
        "`dyn ConsensusQuery` compiled `import_block`. The RPC server's handle \
         reaches proposal acceptance, fork choice and reorg \
         (`PoAEngine::do_import_block`) from an HTTP request with no `PeerId` \
         for the participation check in `Node::admit_peer_block` to judge"
    );
    assert!(
        stderr.contains("import_block"),
        "expected the rejection to name import_block:\n{stderr}"
    );
}

#[test]
fn the_rpc_handle_cannot_produce_a_block() {
    let (failed, stderr) = rejected(
        "fn probe(q: &dyn sumchain_consensus::ConsensusQuery) {\n\
         let _ = q.propose_block(Vec::new());\n\
         }",
    );
    assert!(
        failed,
        "`dyn ConsensusQuery` compiled `propose_block`; an HTTP request can mint \
         a block from this node's validator key"
    );
    assert!(
        stderr.contains("propose_block"),
        "expected the rejection to name propose_block:\n{stderr}"
    );
}

#[test]
fn the_rpc_handle_cannot_drive_engine_lifecycle_or_genesis() {
    // Stopping the engine from an RPC call is a liveness hole; re-seeding
    // genesis under a running chain is a state hole. Neither is a read.
    for (what, program) in [
        (
            "start",
            "fn probe(q: &dyn sumchain_consensus::ConsensusQuery) { let _ = q.start(); }",
        ),
        (
            "stop",
            "fn probe(q: &dyn sumchain_consensus::ConsensusQuery) { let _ = q.stop(); }",
        ),
        (
            "init_genesis",
            "fn probe(q: &dyn sumchain_consensus::ConsensusQuery) {\n\
             let _ = q.init_genesis(unimplemented!());\n\
             }",
        ),
        (
            "load_chain",
            "fn probe(q: &dyn sumchain_consensus::ConsensusQuery) { let _ = q.load_chain(); }",
        ),
    ] {
        let (failed, stderr) = rejected(program);
        assert!(
            failed,
            "`dyn ConsensusQuery` compiled `{what}`; the RPC handle is supposed \
             to be reads of already-decided state only:\n{stderr}"
        );
    }
}

#[test]
fn the_rpc_handle_carries_no_unused_engine_reads() {
    // The trait is sized by what the RPC server ACTUALLY calls, not by a
    // read/write taxonomy. `subscribe`, `is_proposer` and `get_block_by_height`
    // are reads, and are still absent, because no RPC method uses them. Adding
    // one is a deliberate, reviewable widening — this probe is what makes it
    // deliberate rather than incidental.
    for (what, program) in [
        (
            "subscribe",
            "fn probe(q: &dyn sumchain_consensus::ConsensusQuery) { let _ = q.subscribe(); }",
        ),
        (
            "is_proposer",
            "fn probe(q: &dyn sumchain_consensus::ConsensusQuery) { let _ = q.is_proposer(1); }",
        ),
        (
            "get_block_by_height",
            "fn probe(q: &dyn sumchain_consensus::ConsensusQuery) {\n\
             let _ = q.get_block_by_height(1);\n\
             }",
        ),
    ] {
        let (failed, stderr) = rejected(program);
        assert!(
            failed,
            "`dyn ConsensusQuery` compiled `{what}`, which no RPC method calls; \
             the handle has drifted wider than its stated demand:\n{stderr}"
        );
    }
}

#[test]
fn the_narrowed_handle_cannot_be_widened_back() {
    // The narrowing is only worth anything if it is one-way. `ConsensusEngine`
    // is a SUBtrait of `ConsensusQuery`, so `dyn ConsensusEngine` upcasts to
    // `dyn ConsensusQuery` (which is how the node hands the handle over) — and
    // there is no route back: no `Any` supertrait, hence no downcast.
    for (what, program) in [
        (
            "reference coercion",
            "fn probe(q: &dyn sumchain_consensus::ConsensusQuery) {\n\
             let _e: &dyn sumchain_consensus::ConsensusEngine = q;\n\
             }",
        ),
        (
            "Arc coercion",
            "fn probe(q: std::sync::Arc<dyn sumchain_consensus::ConsensusQuery>) {\n\
             let _e: std::sync::Arc<dyn sumchain_consensus::ConsensusEngine> = q;\n\
             }",
        ),
        (
            "Any downcast",
            "fn probe(q: &dyn sumchain_consensus::ConsensusQuery) {\n\
             let _a: &dyn std::any::Any = q;\n\
             }",
        ),
    ] {
        let (failed, stderr) = rejected(program);
        assert!(
            failed,
            "`dyn ConsensusQuery` was convertible back to the full engine by \
             {what}; the narrowing is cosmetic and the capability is still \
             reachable from the RPC server:\n{stderr}"
        );
    }
}
