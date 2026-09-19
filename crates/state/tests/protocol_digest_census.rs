//! The census: every limit-shaped constant in `crates/state/src` and
//! `crates/storage/src` is classified, and a new one fails this test until
//! somebody classifies it.
//!
//! `sumchain_state::protocol_digest::consensus_limits` is only worth reading if
//! it is EXHAUSTIVE. A registry maintained by discipline drifts the moment
//! somebody adds a constant without thinking about it — and the constant they
//! add without thinking about it is exactly the one that forks the chain.
//!
//! This is the same device as
//! `genesis/tests/activation_digest.rs::every_activation_height_is_covered_by_the_digest`,
//! which reads the `ChainParams` field declarations out of the source rather
//! than trusting a list beside them. It cannot be quite that clean here, because
//! "is this constant consensus-relevant" is a judgement and not a type: there is
//! no equivalent of `Option<u64>` to match on. So the scan matches the SHAPE of
//! a limit's name and then requires every hit to appear in exactly one of two
//! explicit lists — the registry, or [`EXCLUDED`] with a stated reason.
//!
//! The ratchet is the point. A new `MAX_…` constant lands in neither list, this
//! test fails, and the author has to write down which it is.

use std::collections::HashSet;

use sumchain_state::protocol_digest::consensus_limits;

/// Constants whose name matches the limit shape and that are deliberately NOT
/// folded into the protocol digest, each with the reason.
///
/// The rule applied throughout: a value belongs in the digest when two binaries
/// holding different values for it would disagree about whether a transaction is
/// valid or about what a committed digest commits to. A value belongs here when
/// it only changes what one node logs, prunes, paginates, restores or answers an
/// RPC query with. Nodes already differ on those deliberately, and folding them
/// in would make the digest report mismatches that are not consensus mismatches
/// — which would train operators to ignore it.
const EXCLUDED: &[(&str, &str)] = &[
    // ── Observability. Warn/act logging thresholds on the account-row count.
    //    Changing one changes when a node prints a line.
    (
        "ACCOUNT_ROW_WARN_THRESHOLD",
        "operator telemetry; no execution effect",
    ),
    (
        "ACCOUNT_ROW_ACT_THRESHOLD",
        "operator telemetry; no execution effect",
    ),
    // ── RPC-side work bounds and paging. Never reached from block execution.
    (
        "MAX_ASSIGNED_COUNT_CHUNK_COUNT",
        "RPC work bound; above it the coverage RPC returns None and the client \
         recomputes locally. Block execution never reads it",
    ),
    (
        "MAX_EDU_LIST_LIMIT",
        "clamp on read-only list helpers called only from the RPC server",
    ),
    // ── Node-local undo journal. `db.rs` states the APPLICATION_JOURNAL column
    //    family is "Never hashed into a block and never read by consensus", and
    //    `activation_multinode.rs` makes the same point: two nodes holding
    //    different journal boundaries CANNOT fork.
    (
        "AFTER_DOMAIN",
        "node-local undo journal; never hashed into a block",
    ),
    (
        "SUPPORTED_JOURNAL_VERSIONS",
        "node-local undo journal; gates whether a node can revert, not what a \
         block computes. A mismatch stalls one node, it does not fork the chain",
    ),
    // ── Node-local snapshot artefacts. `snapshot.rs` states snapshots are
    //    "node-local artefacts — never hashed into a block".
    ("SNAPSHOT_VERSION", "node-local snapshot artefact"),
    (
        "MIN_SUPPORTED_SNAPSHOT_VERSION",
        "node-local snapshot artefact",
    ),
    // ── Operator-seed provenance, present only on a node whose registry did not
    //    come from its own execution.
    (
        "REGISTRY_SEED_DIGEST_CONTEXT",
        "domain separation for an operator-seed provenance record; not read by \
         the executor",
    ),
    // ── A node's self-check that the candidate it is publishing matches the
    //    block it executed. Never in a header, never compared across nodes: each
    //    binary is internally consistent under any value.
    (
        "SUBJECT_TX_DOMAIN",
        "intra-node candidate/block self-check; never crosses the wire",
    ),
    // ── Column-family names and META bookkeeping keys. Single-source string
    //    literals that every other module aliases rather than redeclares, so
    //    cross-binary drift would require editing one file, and the value names
    //    a location rather than deciding a rule.
    (
        "BLOCK_HEIGHT",
        "a column-family name: it names where rows live, it does not decide a rule",
    ),
    (
        "LATEST_BLOCK_HEIGHT",
        "node-local chain-tip bookkeeping key in cf::META",
    ),
    (
        "FINALIZED_HEIGHT",
        "node-local chain-tip bookkeeping key in cf::META",
    ),
    // ── Row KEYS inside the messaging config family. The VALUES they address
    //    are consensus state read from the database, which is the thing every
    //    node already agrees about by reading the same rows; the key literal
    //    only names where to look.
    (
        "MAX_MESSAGE_SIZE",
        "row key in cf::MESSAGING_CONFIG, not a compiled-in limit",
    ),
    (
        "MIN_TRUST_STAKE",
        "row key in cf::MESSAGING_CONFIG, not a compiled-in limit",
    ),
    (
        "SPAM_THRESHOLD",
        "row key in cf::MESSAGING_CONFIG, not a compiled-in limit",
    ),
    // ── This digest's own domain separator. It cannot fold itself: the value
    //    would have to be in its own preimage.
    (
        "PROTOCOL_DIGEST_DOMAIN",
        "the protocol digest's own domain separator; it is the fold, not an \
         input to the fold",
    ),
    // ── Test-only constants.
    ("TEST_LIMIT", "declared inside a #[cfg(test)] module"),
    (
        "ACTIVATION_HEIGHT",
        "test fixture inside a #[cfg(test)] module",
    ),
    (
        "EXPECTED_HEIGHT",
        "test fixture inside a #[cfg(test)] module",
    ),
];

/// Names matching this shape are constants a reader would expect to find
/// classified. Deliberately broad: a false positive costs one line in
/// [`EXCLUDED`], a false negative costs a fork.
fn looks_like_a_limit(name: &str) -> bool {
    name.starts_with("MAX_")
        || name.starts_with("MIN_")
        || [
            "_LIMIT",
            "_DOMAIN",
            "_VERSION",
            "_VERSIONS",
            "_THRESHOLD",
            "_BPS",
            "_SCAFFOLD",
            "_CONTEXT",
            "_PREFIX",
            "_TAG",
            "_HEIGHT",
        ]
        .iter()
        .any(|suffix| name.ends_with(suffix))
}

/// Every `const NAME` declared under `dir`, recursively.
fn declared_constants(dir: &str) -> HashSet<String> {
    fn walk(dir: &std::path::Path, out: &mut HashSet<String>) {
        for entry in std::fs::read_dir(dir).expect("read source directory") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                walk(&path, out);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let src = std::fs::read_to_string(&path).expect("read source file");
            for line in src.lines() {
                let line = line.trim();
                let rest = line
                    .strip_prefix("pub const ")
                    .or_else(|| line.strip_prefix("const "));
                let Some(rest) = rest else { continue };
                let Some((name, _)) = rest.split_once(':') else {
                    continue;
                };
                let name = name.trim();
                // `const fn …` and generic const params are not const items.
                if name.is_empty()
                    || !name
                        .chars()
                        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
                {
                    continue;
                }
                out.insert(name.to_string());
            }
        }
    }

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/")
        .join(dir);
    let mut out = HashSet::new();
    walk(&root, &mut out);
    out
}

/// Every limit-shaped constant is either folded into the digest or explicitly
/// excused.
///
/// This is the test that makes the registry a claim rather than a list. It reads
/// the declarations out of `state/src` and `storage/src`, so a constant added
/// tomorrow is caught tomorrow.
#[test]
fn every_limit_shaped_constant_is_classified() {
    let mut declared = declared_constants("state/src");
    declared.extend(declared_constants("storage/src"));
    assert!(
        declared.len() > 100,
        "the source scan found only {} constants, which means the pattern \
         stopped matching rather than that the constants disappeared",
        declared.len()
    );

    let shaped: HashSet<String> = declared
        .into_iter()
        .filter(|n| looks_like_a_limit(n))
        .collect();
    assert!(
        shaped.len() > 30,
        "the shape filter matched only {} names; it stopped working",
        shaped.len()
    );

    let included: HashSet<String> = consensus_limits()
        .into_iter()
        .map(|(n, _)| n.to_string())
        .collect();
    let excluded: HashSet<String> = EXCLUDED.iter().map(|(n, _)| n.to_string()).collect();

    let unclassified: Vec<&String> = shaped
        .iter()
        .filter(|n| !included.contains(*n) && !excluded.contains(*n))
        .collect();
    assert!(
        unclassified.is_empty(),
        "these constants look like consensus limits and are classified in \
         neither direction. Each is a number or byte string compiled into this \
         binary; if it decides validity, fold it into \
         `protocol_digest::consensus_limits`, and if it does not, add it to \
         EXCLUDED in this file with the reason: {unclassified:?}"
    );
}

/// Nothing is in both lists, and nothing is in a list without existing.
///
/// A name in both would make the classification meaningless. A name in EXCLUDED
/// that no longer exists is a reason nobody can check, and worse, it silently
/// excuses a future constant that happens to reuse the name.
#[test]
fn the_classification_lists_are_disjoint_and_live() {
    let included: HashSet<String> = consensus_limits()
        .into_iter()
        .map(|(n, _)| n.to_string())
        .collect();
    let excluded: HashSet<String> = EXCLUDED.iter().map(|(n, _)| n.to_string()).collect();

    let both: Vec<&String> = included.intersection(&excluded).collect();
    assert!(
        both.is_empty(),
        "these names are both folded into the digest and excused from it: {both:?}"
    );

    let mut declared = declared_constants("state/src");
    declared.extend(declared_constants("storage/src"));

    let stale: Vec<&(&str, &str)> = EXCLUDED
        .iter()
        .filter(|(n, _)| !declared.contains(*n))
        .collect();
    assert!(
        stale.is_empty(),
        "these names are excused from the protocol digest and no longer exist, \
         so the exemption now guards nothing and would silently excuse a future \
         constant reusing the name: {stale:?}"
    );

    for (name, reason) in EXCLUDED {
        assert!(
            reason.len() > 20,
            "{name} is excused from the protocol digest without a reason a \
             reviewer can weigh"
        );
    }
}

/// The three constants the defect report named are folded, by name.
///
/// Spelled out separately from the scan because the scan would still pass if all
/// three were moved into EXCLUDED. They are the reason this module exists.
#[test]
fn the_three_named_binary_constants_are_folded() {
    let included: HashSet<String> = consensus_limits()
        .into_iter()
        .map(|(n, _)| n.to_string())
        .collect();
    for name in [
        "MAX_SUBSYSTEM_PAYLOAD_BYTES",
        "MAX_ACCUMULATING_ROW_BYTES",
        "MAX_NFT_BATCH_MINT_REQUESTS",
    ] {
        assert!(
            included.contains(name),
            "{name} decides whether a transaction is valid once its gate is \
             open and must be folded into the protocol digest"
        );
    }
}
