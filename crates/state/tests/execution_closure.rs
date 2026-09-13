//! The execution-mutation closure: what block execution can still commit, and
//! through which column families.
//!
//! # Why the other guard is not enough
//!
//! `execution_boundary.rs` counts `db.put(` / `db.delete(` / `db.batch(` inside
//! `crates/state/src`. That is a RAW-SYNTAX check, and it reads 3 — which is
//! true and almost meaningless, because nearly every committed write during
//! block execution goes through a store API rather than a database handle:
//!
//! ```ignore
//! store.identity_roots().put(&identity)?;   // -> IdentityRootStore::put -> db.put
//! state.put_account(&addr, &acct)?;         // -> StateStore::put_account -> db.put
//! ```
//!
//! Neither line contains `db.put`, neither is in `crates/state/src`'s syntax
//! budget, and both commit application state in the middle of a block that may
//! never be accepted. A cross-crate audit at `20544f8a` found **317 such sites
//! across 116 application column families**, against a ratchet reading 3.
//!
//! # What this file does instead
//!
//! It computes the CLOSURE: every function that can reach a concrete database
//! mutation, following store constructions, accessor hops, `StateManager`,
//! struct fields, parameters and the contract flush — then counts the call sites
//! that block execution can reach, and pins them to a recorded ledger that may
//! only move down.
//!
//! The ledger is per-file, not a single total, so a write removed from one
//! subsystem cannot pay for a write added to another.
//!
//! # What is deliberately NOT counted
//!
//! Four write classes are legitimate and stay out of the execution ledger, but
//! they are CLASSIFIED rather than ignored — [`non_execution_paths_are_classified`]
//! pins each one, so a new writer cannot hide by claiming one of these labels:
//!
//! * GENESIS — no block exists to abandon.
//! * REORG-UNDO — the committed write that unwinds a published block.
//! * CHAIN STORAGE — blocks, transactions, receipts, their indexes, validator
//!   sets. Not application state; the application journal will not cover them.
//! * SNAPSHOT — fast-sync restore, outside consensus.
//!
//! A fifth is not legitimate: OPERATOR TOOLING. See
//! [`operator_tooling_writes_are_declared_deployment_blockers`].

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};

// ═══════════════════════════════════════════════════════════════════════════
// THE LEDGER
// ═══════════════════════════════════════════════════════════════════════════

/// Committed write sites reachable from block execution, per file.
///
/// ONLY EVER DECREASE THESE. This is the inventory the application journal has
/// to empty; a number that grows is a new way for an unaccepted block to change
/// canonical state.
///
/// Recorded at `20544f8a`, the commit that finished the storage-metadata and
/// node-registry cluster. The subsystems absent from this list — education,
/// inference attestation, inference settlement, supply, node registry, storage
/// metadata, compute pool, beacon — write through the overlay and have no entry
/// to lose.
fn execution_ledger() -> BTreeMap<&'static str, usize> {
    BTreeMap::from([
        ("crates/state/src/agreement_executor.rs", 20),
        ("crates/state/src/docclass_executor.rs", 46),
        ("crates/state/src/employment_executor.rs", 13),
        ("crates/state/src/equity_executor.rs", 12),
        ("crates/state/src/executor.rs", 1),
        ("crates/state/src/finance_executor.rs", 14),
        ("crates/state/src/governance_executor.rs", 9),
        ("crates/state/src/healthcare_executor.rs", 29),
        ("crates/state/src/legal_executor.rs", 26),
        ("crates/state/src/messaging_executor.rs", 26),
        ("crates/state/src/nft_executor.rs", 17),
        ("crates/state/src/policy_account_executor.rs", 8),
        ("crates/state/src/property_executor.rs", 31),
        ("crates/state/src/staking_executor.rs", 28),
        ("crates/state/src/state.rs", 9),
        ("crates/state/src/tax_executor.rs", 11),
        ("crates/state/src/token_executor.rs", 17),
    ])
}

/// Application column families a block can still commit to directly.
///
/// ONLY EVER DECREASE. Recorded at `20544f8a`.
const LEDGER_CF_COUNT: usize = 116;

/// Column families declared in `sumchain_storage::cf` that nothing reads or
/// writes anywhere in the workspace.
///
/// Dead schema. They are created at open and never touched again. They must NOT
/// enter the journal allowlist — journalling a family no code uses would make
/// the journal look more complete than it is, and would keep the dead
/// declarations alive by giving them a reader.
const DEAD_COLUMN_FAMILIES: &[&str] = &[
    "EDU_CATALOG_ACCREDITATION",
    "EDU_CATALOG_PREREQUISITES",
    "EDU_INSTRUCTOR_BINDINGS",
    "FINANCE_HOLDER_ADDRESS_PROOF_INDEX",
    "FINANCE_HOLDER_BANK_INDEX",
    "FINANCE_HOLDER_KYC_INDEX",
    "HEALTHCARE_MEMBER_ADDRESS_INDEX",
    "HEALTHCARE_PATIENT_ADDRESS_INDEX",
    "HEALTHCARE_SUBJECT_ADDRESS_INDEX",
    "TAX_ISSUER_INDEX",
];

// ═══════════════════════════════════════════════════════════════════════════
// DISPATCHER ARMS
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArmKind {
    /// Writes only through `ExecutionView`. Nothing to migrate.
    Overlay,
    /// Commits application state during execution.
    Committed,
    /// Takes an `ExecutionView` AND a committed handle, and uses both.
    Mixed,
}

/// Every `TxPayload` variant the block dispatcher handles, with where it writes.
///
/// The list is closed: [`every_dispatcher_arm_is_declared`] fails if the
/// executor gains or loses an arm, so a new transaction family cannot arrive
/// with an undeclared write surface.
const ARMS: &[(&str, ArmKind, &str)] = &[
    ("Agreement", ArmKind::Committed, "agreement_executor.rs -> AgreementStore sub-stores"),
    ("BeaconSetup", ArmKind::Overlay, "beacon_store.rs (revert stays direct, by design)"),
    ("BeaconSigning", ArmKind::Overlay, "beacon_store.rs (revert stays direct, by design)"),
    ("ComputePool", ArmKind::Overlay, "compute_pool_store.rs (revert stays direct, by design)"),
    ("ContractCall", ArmKind::Committed, "sumc-runtime RocksDbStorage; own buffer + ContractMutation journal"),
    ("ContractDeploy", ArmKind::Committed, "sumc-runtime RocksDbStorage; own buffer + ContractMutation journal"),
    ("DocClass", ArmKind::Committed, "docclass_executor.rs -> DocClassStore sub-stores"),
    ("Education", ArmKind::Overlay, "education_executor.rs"),
    ("Employment", ArmKind::Committed, "employment_executor.rs -> EmploymentStore sub-stores"),
    ("Equity", ArmKind::Committed, "equity_executor.rs -> EquityStore sub-stores"),
    ("Finance", ArmKind::Committed, "finance_executor.rs -> FinanceStore sub-stores"),
    ("Governance", ArmKind::Mixed, "governance_executor.rs takes a view AND a db; GovStore/TokenStore/EquityStore are committed"),
    ("Healthcare", ArmKind::Committed, "healthcare_executor.rs -> HealthcareStore sub-stores"),
    ("InferenceAttestation", ArmKind::Overlay, "inference_attestation_executor.rs"),
    ("InferenceAttestationV2", ArmKind::Overlay, "inference_attestation_executor.rs"),
    ("InferenceSettlement", ArmKind::Overlay, "inference_settlement_executor.rs"),
    ("Legal", ArmKind::Committed, "legal_executor.rs -> LegalStore sub-stores"),
    ("Messaging", ArmKind::Committed, "messaging_executor.rs -> MessagingStore"),
    ("Nft", ArmKind::Committed, "nft_executor.rs -> NftStore"),
    ("NodeRegistry", ArmKind::Overlay, "node_registry.rs"),
    ("NodeRegistryV2", ArmKind::Overlay, "node_registry.rs"),
    ("PolicyAccount", ArmKind::Committed, "policy_account_executor.rs -> PolicyAccountStorage"),
    ("Property", ArmKind::Committed, "property_executor.rs -> PropertyStore sub-stores"),
    ("Staking", ArmKind::Committed, "staking_executor.rs -> Staking/Delegation/SlashingStore"),
    ("StorageMetadata", ArmKind::Overlay, "storage_metadata.rs"),
    ("StorageMetadataV2", ArmKind::Overlay, "storage_metadata.rs"),
    ("Supply", ArmKind::Overlay, "supply.rs"),
    ("Tax", ArmKind::Committed, "tax_executor.rs -> TaxStore sub-stores"),
    ("Token", ArmKind::Committed, "token_executor.rs -> TokenStore"),
    ("Transfer", ArmKind::Committed, "executor.rs fee/transfer -> StateManager::put_account -> cf::STATE"),
];

/// Every arm's fee and nonce path debits an ACCOUNT row through
/// `StateManager::put_account`, including the twelve that are otherwise
/// overlay-only. Accounts are the widest single hole and migrate first.
const ACCOUNT_WRITE_IS_UNIVERSAL: &str =
    "StateManager::put_account -> StateStore::put_account -> db.put(cf::STATE)";

// ═══════════════════════════════════════════════════════════════════════════
// THE SCANNER
// ═══════════════════════════════════════════════════════════════════════════
//
// Source-level, like the raw-syntax guard next door, and with the same honesty
// about what that means: this catches the shapes the codebase actually uses, not
// every shape Rust permits. What makes it worth having is that the shapes it
// follows — store construction, accessor hops, fields, parameters, helper
// indirection — are exactly the ones that made 317 sites invisible to a check
// that only knew `db.put`.
//
// Every resolution rule below is exercised by a synthetic-source test at the
// bottom of this file, and each of those tests was written by breaking the rule
// and watching the count drop.

/// The workspace root: `crates/state/..`.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

/// Crates whose `src/` is test scaffolding rather than production code.
/// `sumchain-integration-tests` is a library of tests: its modules are plain
/// `mod`s, not `#[cfg(test)]`, so stripping attributes does not reach them.
const TEST_ONLY_CRATES: &[&str] = &["crates/integration-tests/"];

/// Files that buffer rather than commit.
///
/// `ApplicationOverlay` ends in a `db.batch()` — but only inside
/// `into_batch`, which is crate-private to `sumchain-storage` and reachable
/// only from `AcceptedCandidate::publish`. Treating an overlay write as a
/// committed write would count every migrated subsystem as unmigrated, which is
/// the exact opposite of what this ledger measures.
const BUFFERING_FILES: &[&str] = &[
    "crates/storage/src/overlay.rs",
    "crates/storage/src/exec_view.rs",
    "crates/storage/src/candidate.rs",
];

/// Production `.rs` sources under every crate's `src/`, keyed by workspace-
/// relative path. `#[cfg(test)]` modules and comment lines are removed first:
/// a fixture is not block execution, and a commented-out write is not a write.
fn production_sources() -> BTreeMap<String, String> {
    let root = workspace_root();
    let crates = root.join("crates");
    let mut out = BTreeMap::new();
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(&crates)
        .expect("read crates/")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_dir())
        .map(|p| p.join("src"))
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();
    for src_dir in dirs {
        walk(&src_dir, &root, &mut out);
    }
    out
}

fn walk(dir: &Path, root: &Path, out: &mut BTreeMap<String, String>) {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .expect("read source directory")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            walk(&path, root, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            let src = std::fs::read_to_string(&path).expect("read source");
            let rel = path
                .strip_prefix(root)
                .expect("path under the workspace root")
                .to_string_lossy()
                .replace('\\', "/");
            if TEST_ONLY_CRATES.iter().any(|c| rel.starts_with(c)) {
                continue;
            }
            out.insert(rel, prepare(&src));
        }
    }
}

/// Drop `#[cfg(test)]` items and comment lines, preserving line numbering so a
/// reported site can be opened at the line the scanner names.
fn prepare(src: &str) -> String {
    let no_comments: String = src
        .lines()
        .map(|l| {
            let t = l.trim_start();
            if t.starts_with("//") {
                ""
            } else {
                l
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    strip_cfg_test(&no_comments)
}

/// Remove every `#[cfg(test)]` item, blanking it in place so line numbers hold.
fn strip_cfg_test(src: &str) -> String {
    const ATTR: &str = "#[cfg(test)]";
    let mut out = src.to_string();
    let mut from = 0usize;
    while let Some(rel) = out[from..].find(ATTR) {
        let at = from + rel;
        // The item's body is the next balanced `{ .. }`; a `#[cfg(test)] use ..;`
        // or `mod x;` ends at the semicolon instead.
        let after = at + ATTR.len();
        let brace = out[after..].find('{').map(|i| after + i);
        let semi = out[after..].find(';').map(|i| after + i);
        let end = match (brace, semi) {
            (Some(b), Some(s)) if s < b => s + 1,
            (Some(b), _) => match matching(&out, b, b'{', b'}') {
                Some(e) => e + 1,
                None => break,
            },
            (None, Some(s)) => s + 1,
            (None, None) => break,
        };
        // Byte-for-byte, so every offset after this point still addresses the
        // same source position: a multi-byte character becomes that many
        // spaces, and newlines survive so line numbers hold.
        let mut blanked = String::with_capacity(end - at);
        for c in out[at..end].chars() {
            if c == '\n' {
                blanked.push('\n');
            } else {
                for _ in 0..c.len_utf8() {
                    blanked.push(' ');
                }
            }
        }
        out.replace_range(at..end, &blanked);
        from = end;
    }
    out
}

fn matching(s: &str, open: usize, o: u8, c: u8) -> Option<usize> {
    let b = s.as_bytes();
    let mut depth = 0usize;
    let mut i = open;
    while i < b.len() {
        match b[i] {
            x if x == o => depth += 1,
            x if x == c => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            b'"' => i = skip_string(b, i)?.saturating_sub(1),
            _ => {}
        }
        i += 1;
    }
    None
}

/// Index just past a double-quoted string starting at `at`.
fn skip_string(b: &[u8], at: usize) -> Option<usize> {
    let mut i = at + 1;
    while i < b.len() {
        match b[i] {
            b'\\' => i += 2,
            b'"' => return Some(i + 1),
            _ => i += 1,
        }
    }
    None
}

#[derive(Debug, Clone)]
struct Fun {
    file: String,
    owner: Option<String>,
    name: String,
    params: String,
    body: String,
    /// Byte offset of the body's opening brace, for line attribution.
    body_at: usize,
}

struct Index {
    funs: Vec<Fun>,
    /// `struct Name { field: Type }`
    fields: HashMap<String, HashMap<String, String>>,
    /// `impl Type { fn acc(&self) -> Ret }`
    accessors: HashMap<(String, String), String>,
    by_owner: HashMap<(String, String), Vec<usize>>,
    /// Line-start byte offsets per file, for `line_of`.
    line_starts: HashMap<String, Vec<usize>>,
}

fn ident_start(c: u8) -> bool {
    c.is_ascii_alphabetic() || c == b'_'
}
fn ident_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

/// The identifier beginning at `i`, if any.
fn ident_at(b: &[u8], i: usize) -> Option<(String, usize)> {
    if i >= b.len() || !ident_start(b[i]) {
        return None;
    }
    let mut j = i;
    while j < b.len() && ident_char(b[j]) {
        j += 1;
    }
    Some((String::from_utf8_lossy(&b[i..j]).to_string(), j))
}

/// Index past whitespace from `i`.
fn skip_ws(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && (b[i] as char).is_whitespace() {
        i += 1;
    }
    i
}

/// The first type-looking identifier in a type expression, e.g. `Arc<Database>`
/// yields `Arc`, `&mut TokenStore<'_>` yields `TokenStore`. `Arc`/`Vec`/`Option`
/// and friends are unwrapped so `Arc<Database>` resolves to `Database`.
fn type_head(s: &str) -> Option<String> {
    const WRAPPERS: &[&str] = &["Arc", "Rc", "Box", "Option", "Vec", "RwLock", "Mutex", "Result"];
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if ident_start(b[i]) {
            let (id, j) = ident_at(b, i)?;
            if WRAPPERS.contains(&id.as_str()) {
                i = j;
                continue;
            }
            if id.chars().next().is_some_and(|c| c.is_ascii_uppercase()) {
                return Some(id);
            }
            i = j;
        } else {
            i += 1;
        }
    }
    None
}

/// Parse one file into functions, struct fields and accessor return types.
fn index_file(file: &str, src: &str, idx: &mut Index) {
    let b = src.as_bytes();

    // Line starts, for attribution.
    let mut starts = vec![0usize];
    for (i, c) in src.char_indices() {
        if c == '\n' {
            starts.push(i + 1);
        }
    }
    idx.line_starts.insert(file.to_string(), starts);

    // `impl [Trait for] Type { .. }` spans, so a fn can be attributed to its type.
    let mut impls: Vec<(usize, usize, String)> = Vec::new();
    let mut i = 0usize;
    while let Some(rel) = src[i..].find("impl") {
        let at = i + rel;
        i = at + 4;
        // Must be the keyword, not part of an identifier.
        if at > 0 && ident_char(b[at - 1]) {
            continue;
        }
        if at + 4 < b.len() && ident_char(b[at + 4]) {
            continue;
        }
        let Some(open) = src[at..].find('{').map(|k| at + k) else {
            continue;
        };
        let head = &src[at + 4..open];
        // `impl<..> Trait for Type` -> Type; `impl<..> Type` -> Type.
        let subject = match head.rfind(" for ") {
            Some(k) => &head[k + 5..],
            None => head,
        };
        let Some(ty) = type_head(subject) else { continue };
        let Some(close) = matching(src, open, b'{', b'}') else {
            continue;
        };
        impls.push((open, close, ty));
    }

    // `struct Name { field: Type, .. }`
    let mut i = 0usize;
    while let Some(rel) = src[i..].find("struct ") {
        let at = i + rel;
        i = at + 7;
        if at > 0 && ident_char(b[at - 1]) {
            continue;
        }
        let Some((name, after)) = ident_at(b, skip_ws(b, at + 7)) else {
            continue;
        };
        let Some(open) = src[after..].find('{').map(|k| after + k) else {
            continue;
        };
        // A tuple struct or a `struct X;` has no brace before the next `;`.
        if let Some(semi) = src[after..].find(';').map(|k| after + k) {
            if semi < open {
                continue;
            }
        }
        let Some(close) = matching(src, open, b'{', b'}') else {
            continue;
        };
        let entry = idx.fields.entry(name).or_default();
        for line in src[open + 1..close].split(',') {
            let line = line.trim();
            let Some(colon) = line.find(':') else { continue };
            let fname = line[..colon].trim();
            let fname = fname.rsplit(' ').next().unwrap_or(fname); // drop `pub`
            if fname.is_empty() || !ident_start(fname.as_bytes()[0]) {
                continue;
            }
            if let Some(ty) = type_head(&line[colon + 1..]) {
                entry.insert(fname.to_string(), ty);
            }
        }
    }

    // Functions.
    let mut i = 0usize;
    while let Some(rel) = src[i..].find("fn ") {
        let at = i + rel;
        i = at + 3;
        if at > 0 && ident_char(b[at - 1]) {
            continue;
        }
        let Some((name, after)) = ident_at(b, skip_ws(b, at + 3)) else {
            continue;
        };
        // Parameter list: first `(` after the name (generics may intervene).
        let Some(popen) = src[after..].find('(').map(|k| after + k) else {
            continue;
        };
        let Some(pclose) = matching(src, popen, b'(', b')') else {
            continue;
        };
        let rest = &src[pclose + 1..];
        let bopen_rel = rest.find('{');
        let semi_rel = rest.find(';');
        let Some(bo) = bopen_rel else { continue };
        if let Some(s) = semi_rel {
            if s < bo {
                continue; // a declaration, not a definition
            }
        }
        let body_at = pclose + 1 + bo;
        let Some(bclose) = matching(src, body_at, b'{', b'}') else {
            continue;
        };
        let owner = impls
            .iter()
            .filter(|(o, c, _)| *o < at && at < *c)
            .map(|(_, _, t)| t.clone())
            .next_back();
        // An accessor: `fn acc(&self) -> Ret`.
        if let Some(ref o) = owner {
            let params = &src[popen + 1..pclose];
            if params.trim_start().starts_with("&self") {
                if let Some(arrow) = rest[..bo].find("->") {
                    if let Some(ret) = type_head(&rest[arrow + 2..bo]) {
                        idx.accessors.insert((o.clone(), name.clone()), ret);
                    }
                }
            }
        }
        let f = Fun {
            file: file.to_string(),
            owner: owner.clone(),
            name: name.clone(),
            params: src[popen + 1..pclose].to_string(),
            body: src[body_at..=bclose].to_string(),
            body_at,
        };
        let k = idx.funs.len();
        idx.by_owner
            .entry((owner.unwrap_or_default(), name))
            .or_default()
            .push(k);
        idx.funs.push(f);
        i = body_at;
    }
}

fn build_index(sources: &BTreeMap<String, String>) -> Index {
    let mut idx = Index {
        funs: Vec::new(),
        fields: HashMap::new(),
        accessors: HashMap::new(),
        by_owner: HashMap::new(),
        line_starts: HashMap::new(),
    };
    for (file, src) in sources {
        index_file(file, src, &mut idx);
    }
    idx
}

fn line_of(idx: &Index, file: &str, offset: usize) -> usize {
    let starts = &idx.line_starts[file];
    match starts.binary_search(&offset) {
        Ok(k) => k + 1,
        Err(k) => k,
    }
}

// ── Binding resolution ─────────────────────────────────────────────────────
//
// A receiver is resolved by TYPE, never by the name `db`. That is what makes
// renaming a receiver — `db` to `database`, or moving it into a differently
// named field — fail to hide a write.

/// `binding path -> type name` for one function: parameters, `let` bindings,
/// and the fields of the type it is implemented on.
fn bindings(idx: &Index, f: &Fun) -> HashMap<String, String> {
    let mut out = HashMap::new();

    // Parameters: `name: &mut Arc<Type>`.
    for part in split_top_level(&f.params, ',') {
        let part = part.trim();
        let Some(colon) = part.find(':') else { continue };
        let name = part[..colon].trim();
        if name.is_empty() || !ident_start(name.as_bytes()[0]) {
            continue;
        }
        if let Some(ty) = type_head(&part[colon + 1..]) {
            out.insert(name.to_string(), ty);
        }
    }

    // Fields of the implementing type: `self.db`, `self.storage`, ...
    if let Some(owner) = &f.owner {
        if let Some(fs) = idx.fields.get(owner) {
            for (fname, ty) in fs {
                out.insert(format!("self.{fname}"), ty.clone());
            }
        }
    }

    // `let x = Type::new(..)`, `let x: Type = ..`, `let x = <expr>.batch()`.
    let b = f.body.as_bytes();
    let mut i = 0usize;
    while let Some(rel) = f.body[i..].find("let ") {
        let at = i + rel;
        i = at + 4;
        if at > 0 && ident_char(b[at - 1]) {
            continue;
        }
        let mut j = skip_ws(b, at + 4);
        if f.body[j..].starts_with("mut ") {
            j = skip_ws(b, j + 4);
        }
        let Some((name, after)) = ident_at(b, j) else {
            continue;
        };
        let stmt_end = f.body[after..]
            .find(';')
            .map(|k| after + k)
            .unwrap_or(f.body.len());
        let stmt = &f.body[after..stmt_end];
        // An explicit annotation wins.
        if let Some(colon) = stmt.find(':') {
            let eq = stmt.find('=').unwrap_or(stmt.len());
            if colon < eq {
                if let Some(ty) = type_head(&stmt[colon + 1..eq]) {
                    out.insert(name.clone(), ty);
                    continue;
                }
            }
        }
        if stmt.contains(".batch()") {
            out.insert(name.clone(), "WriteBatch".to_string());
            continue;
        }
        if let Some(k) = stmt.find("::new(") {
            if let Some(ty) = type_head_backwards(&stmt[..k]) {
                out.insert(name.clone(), ty);
            }
        }
    }
    out
}

/// The type name immediately preceding a `::new(` — the last capitalised
/// identifier in `s`.
fn type_head_backwards(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut end = b.len();
    while end > 0 {
        let mut start = end;
        while start > 0 && ident_char(b[start - 1]) {
            start -= 1;
        }
        if start < end {
            let id = &s[start..end];
            if id.chars().next().is_some_and(|c| c.is_ascii_uppercase()) {
                return Some(id.to_string());
            }
        }
        if start == 0 {
            return None;
        }
        end = start - 1;
    }
    None
}

/// Split on `sep` at paren/bracket/angle depth zero.
fn split_top_level(s: &str, sep: char) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut cur = String::new();
    for c in s.chars() {
        match c {
            '(' | '[' | '<' => depth += 1,
            ')' | ']' | '>' => depth -= 1,
            _ => {}
        }
        if c == sep && depth == 0 {
            out.push(std::mem::take(&mut cur));
        } else {
            cur.push(c);
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur);
    }
    out
}

// ── Column families ────────────────────────────────────────────────────────

/// A column family a write lands in.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Cf {
    Named(String),
    /// The family came from a runtime binding — `db.put(cf, ..)` where `cf` was
    /// chosen by an `if`. `execute_accept_assignment_v2` was exactly this, and no
    /// name-based check could see it.
    Variable,
}

/// Every `cf::NAME` / `CF_NAME` named in a body.
fn named_cfs(body: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let b = body.as_bytes();
    let mut i = 0usize;
    while i < b.len() {
        if let Some((id, j)) = ident_at(b, i) {
            let upper = id.len() > 3
                && id
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
            if upper {
                // Byte-wise, not by slicing: `i - 4` can land inside a
                // multi-byte character in a file that has one anywhere.
                let after_cf_mod = i >= 4 && &b[i - 4..i] == b"cf::";
                if after_cf_mod {
                    out.insert(id);
                } else if let Some(rest) = id.strip_prefix("CF_") {
                    out.insert(rest.to_string());
                }
            }
            i = j;
        } else {
            i += 1;
        }
    }
    out
}

// ── The closure ────────────────────────────────────────────────────────────

/// Method calls that mutate a database handle or a write batch.
const RAW_MUTATORS: &[&str] = &["put", "delete", "commit"];

/// Types whose `put`/`delete`/`commit` IS a committed database write.
const DB_TYPES: &[&str] = &["Database", "WriteBatch"];

/// Functions that write the database directly, with the families they touch.
///
/// The receiver is resolved by type, so this sees `database.put(..)`,
/// `self.backing.put(..)` and a batch bound under any name. The families are
/// those named in the body; a body that writes through a runtime-chosen family
/// and names none is recorded as [`Cf::Variable`] rather than dropped.
fn raw_sinks(idx: &Index) -> HashMap<usize, BTreeSet<Cf>> {
    let mut out: HashMap<usize, BTreeSet<Cf>> = HashMap::new();
    for (k, f) in idx.funs.iter().enumerate() {
        if BUFFERING_FILES.contains(&f.file.as_str()) {
            continue;
        }
        let binds = bindings(idx, f);
        let mut writes = false;
        for (path, ty) in &binds {
            if !DB_TYPES.contains(&ty.as_str()) {
                continue;
            }
            for m in RAW_MUTATORS {
                if calls_on(&f.body, path, m) {
                    writes = true;
                }
            }
        }
        if !writes {
            continue;
        }
        let named = named_cfs(&f.body);
        let cfs: BTreeSet<Cf> = if named.is_empty() {
            BTreeSet::from([Cf::Variable])
        } else {
            named.into_iter().map(Cf::Named).collect()
        };
        out.insert(k, cfs);
    }
    out
}

/// Does `body` contain `receiver.method(`, tolerating whitespace and line
/// breaks between the receiver, the dot and the name?
///
/// Tolerating them is the point: `self.db\n    .put(cf, &k, &v)` is the single
/// most common shape in this codebase, and matching within one line is how the
/// first version of the raw-syntax guard missed fourteen writes.
fn calls_on(body: &str, receiver: &str, method: &str) -> bool {
    call_offsets(body, receiver, method).next().is_some()
}

/// Byte offsets of every `receiver.method(` in `body`.
fn call_offsets<'a>(
    body: &'a str,
    receiver: &'a str,
    method: &'a str,
) -> impl Iterator<Item = usize> + 'a {
    let mut from = 0usize;
    std::iter::from_fn(move || {
        let b = body.as_bytes();
        loop {
            let rel = body[from..].find(receiver)?;
            let at = from + rel;
            from = at + receiver.len();
            // A whole-token receiver: `db` must not match inside `adb`.
            if at > 0 && ident_char(b[at - 1]) {
                continue;
            }
            let mut i = skip_ws(b, at + receiver.len());
            if b.get(i) != Some(&b'.') {
                continue;
            }
            i = skip_ws(b, i + 1);
            let Some((id, j)) = ident_at(b, i) else {
                continue;
            };
            if id != method {
                continue;
            }
            if b.get(skip_ws(b, j)) != Some(&b'(') {
                continue;
            }
            return Some(at);
        }
    })
}

/// Transitive closure: every function that can reach a raw sink, with the union
/// of the families reachable from it.
///
/// This is the half the raw-syntax guard cannot do. A write moved behind a
/// helper — `fn persist(&self) { self.db.put(..) }`, called from twenty places —
/// leaves the caller with no `db.put` in its body and no reduction in what a
/// block can commit.
fn mutator_closure(idx: &Index, sinks: &HashMap<usize, BTreeSet<Cf>>) -> HashMap<usize, BTreeSet<Cf>> {
    let mut cfs: HashMap<usize, BTreeSet<Cf>> = sinks.clone();
    // `(owner, name) -> callers` is rebuilt each round from resolved edges.
    let mut changed = true;
    let mut rounds = 0;
    while changed {
        changed = false;
        rounds += 1;
        assert!(rounds < 64, "closure did not converge");
        for (k, f) in idx.funs.iter().enumerate() {
            let mut gained: BTreeSet<Cf> = BTreeSet::new();
            for (target, _) in resolved_calls(idx, f, &cfs) {
                if let Some(t) = cfs.get(&target) {
                    gained.extend(t.iter().cloned());
                }
            }
            if gained.is_empty() {
                continue;
            }
            let entry = cfs.entry(k).or_default();
            let before = entry.len();
            entry.extend(gained);
            if entry.len() != before {
                changed = true;
            }
        }
    }
    cfs
}

/// Calls from `f` that resolve to a known mutator, as `(callee index, offset)`.
///
/// Five shapes, all of which the codebase uses:
///
/// * `binding.method(..)`            — a store held in a `let`, a parameter or a field
/// * `binding.accessor().method(..)` — `store.identity_roots().put(..)`
/// * `Type::new(..).method(..)`      — a store constructed inline
/// * `Type::new(..).accessor().method(..)`
/// * `Type::method(..)` / `self.method(..)` — associated and inherent calls
fn resolved_calls(
    idx: &Index,
    f: &Fun,
    known: &HashMap<usize, BTreeSet<Cf>>,
) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let binds = bindings(idx, f);
    let b = f.body.as_bytes();

    let push = |ty: &str, method: &str, at: usize, out: &mut Vec<(usize, usize)>| {
        if let Some(ks) = idx.by_owner.get(&(ty.to_string(), method.to_string())) {
            for &k in ks {
                if known.contains_key(&k) {
                    out.push((k, at));
                }
            }
        }
    };

    // binding.method( .. ) and binding.accessor().method( .. )
    for (path, ty) in &binds {
        let mut from = 0usize;
        while let Some(rel) = f.body[from..].find(path.as_str()) {
            let at = from + rel;
            from = at + path.len();
            if at > 0 && ident_char(b[at - 1]) {
                continue;
            }
            let mut i = skip_ws(b, at + path.len());
            if b.get(i) != Some(&b'.') {
                continue;
            }
            i = skip_ws(b, i + 1);
            let Some((m1, j)) = ident_at(b, i) else {
                continue;
            };
            let k = skip_ws(b, j);
            if b.get(k) != Some(&b'(') {
                continue;
            }
            push(ty, &m1, at, &mut out);
            // One accessor hop: `binding.acc().method(`.
            let Some(close) = matching(&f.body, k, b'(', b')') else {
                continue;
            };
            if f.body[k + 1..close].trim().is_empty() {
                if let Some(ret) = idx.accessors.get(&(ty.clone(), m1.clone())) {
                    let mut p = skip_ws(b, close + 1);
                    if b.get(p) == Some(&b'.') {
                        p = skip_ws(b, p + 1);
                        if let Some((m2, q)) = ident_at(b, p) {
                            if b.get(skip_ws(b, q)) == Some(&b'(') {
                                push(ret, &m2, at, &mut out);
                            }
                        }
                    }
                }
            }
        }
    }

    // Type::method( .. ), including `Type::new(..).method(..)` chains.
    let mut i = 0usize;
    while i < b.len() {
        let Some((id, j)) = ident_at(b, i) else {
            i += 1;
            continue;
        };
        i = j;
        if !id.chars().next().is_some_and(|c| c.is_ascii_uppercase()) {
            continue;
        }
        if !f.body[j..].starts_with("::") {
            continue;
        }
        let Some((m, k)) = ident_at(b, j + 2) else {
            continue;
        };
        let popen = skip_ws(b, k);
        if b.get(popen) != Some(&b'(') {
            continue;
        }
        push(&id, &m, j, &mut out);
        // `Type::new(..)` then `.method(` or `.acc().method(`.
        if m == "new" {
            if let Some(close) = matching(&f.body, popen, b'(', b')') {
                let mut p = skip_ws(b, close + 1);
                if b.get(p) == Some(&b'.') {
                    p = skip_ws(b, p + 1);
                    if let Some((m1, q)) = ident_at(b, p) {
                        let qq = skip_ws(b, q);
                        if b.get(qq) == Some(&b'(') {
                            push(&id, &m1, j, &mut out);
                            if let Some(c2) = matching(&f.body, qq, b'(', b')') {
                                if f.body[qq + 1..c2].trim().is_empty() {
                                    if let Some(ret) = idx.accessors.get(&(id.clone(), m1.clone())) {
                                        let mut r = skip_ws(b, c2 + 1);
                                        if b.get(r) == Some(&b'.') {
                                            r = skip_ws(b, r + 1);
                                            if let Some((m2, s)) = ident_at(b, r) {
                                                if b.get(skip_ws(b, s)) == Some(&b'(') {
                                                    push(ret, &m2, j, &mut out);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // `self.method( .. )` — inherent calls, which carry helper indirection.
    if let Some(owner) = &f.owner {
        for at in call_offsets_any(&f.body, "self") {
            let mut p = skip_ws(b, at + 4);
            if b.get(p) != Some(&b'.') {
                continue;
            }
            p = skip_ws(b, p + 1);
            if let Some((m, q)) = ident_at(b, p) {
                if b.get(skip_ws(b, q)) == Some(&b'(') {
                    push(owner, &m, at, &mut out);
                }
            }
        }
    }
    out
}

/// Offsets of every whole-token occurrence of `tok` in `body`.
fn call_offsets_any<'a>(body: &'a str, tok: &'a str) -> impl Iterator<Item = usize> + 'a {
    let mut from = 0usize;
    std::iter::from_fn(move || {
        let b = body.as_bytes();
        loop {
            let rel = body[from..].find(tok)?;
            let at = from + rel;
            from = at + tok.len();
            if at > 0 && ident_char(b[at - 1]) {
                continue;
            }
            if b.get(at + tok.len()).is_some_and(|&c| ident_char(c)) {
                continue;
            }
            return Some(at);
        }
    })
}

// ── Classification ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Class {
    /// Reachable from a block dispatcher arm or a block-level phase. Counted.
    Execution,
    /// No block exists to abandon.
    Genesis,
    /// The committed write that unwinds an already-published block.
    ReorgUndo,
    /// Blocks, transactions, receipts, their indexes, validator sets, pruning.
    /// Not application state.
    ChainStorage,
    /// Fast-sync restore, outside consensus.
    Snapshot,
    /// An operator CLI that changes application state outside consensus.
    OperatorTooling,
    /// Inside the storage or runtime library itself — these ARE the sinks, and
    /// counting their internal calls would double-count every write.
    Library,
    /// Read-only or write-free surfaces: RPC, mempool, p2p transport, bridge.
    NotAWriter,
}

/// Where a function's writes belong. Everything is classified; nothing is
/// silently dropped.
fn classify(file: &str, fn_name: &str) -> Class {
    if file.starts_with("crates/storage/src") || file.starts_with("crates/sumc-runtime/src") {
        return Class::Library;
    }
    match file {
        "crates/state/src/snapshot.rs" => return Class::Snapshot,
        "crates/node/src/main.rs" => return Class::OperatorTooling,
        "crates/state/src/state.rs" => {
            if fn_name == "init_from_genesis" {
                return Class::Genesis;
            }
            if fn_name.contains("revert") {
                return Class::ReorgUndo;
            }
            return Class::Execution;
        }
        "crates/state/src/beacon_store.rs" | "crates/state/src/compute_pool_store.rs" => {
            return if fn_name.contains("revert") {
                Class::ReorgUndo
            } else {
                Class::Execution
            };
        }
        _ => {}
    }
    if file.starts_with("crates/consensus/src")
        || file.starts_with("crates/p2p/src")
        || file.starts_with("crates/node/src")
    {
        return Class::ChainStorage;
    }
    if file.starts_with("crates/rpc/src") || file.starts_with("crates/bridge/src") {
        return Class::NotAWriter;
    }
    Class::Execution
}

#[derive(Debug, Clone)]
struct Site {
    file: String,
    line: usize,
    class: Class,
    cfs: BTreeSet<Cf>,
}

/// Every call site where APPLICATION code reaches into the storage or runtime
/// library and commits.
///
/// The crossing is what counts, not every hop on the way to it. A write moved
/// behind a private helper is still exactly one site — it just moves to the
/// helper's line, in the same file — so indirection changes where the work is,
/// never how much there is.
///
/// One site per source line: a line calling two mutators is one place to fix,
/// and counting it twice would make the ledger drift on reformatting.
fn all_sites(idx: &Index, closure: &HashMap<usize, BTreeSet<Cf>>) -> Vec<Site> {
    let mut per_line: BTreeMap<(String, usize), (Class, BTreeSet<Cf>)> = BTreeMap::new();
    for f in idx.funs.iter() {
        let class = classify(&f.file, &f.name);
        if class == Class::Library {
            continue; // the library's internals ARE the write, not a site
        }
        for (target, at) in resolved_calls(idx, f, closure) {
            if classify(&idx.funs[target].file, &idx.funs[target].name) != Class::Library {
                continue; // application-to-application indirection, not a crossing
            }
            let Some(cfs) = closure.get(&target) else {
                continue;
            };
            let line = line_of(idx, &f.file, f.body_at + at);
            let e = per_line
                .entry((f.file.clone(), line))
                .or_insert((class, BTreeSet::new()));
            e.1.extend(cfs.iter().cloned());
        }
    }
    per_line
        .into_iter()
        .map(|((file, line), (class, cfs))| Site { file, line, class, cfs })
        .collect()
}

/// Run the whole analysis over an arbitrary source map. Split out so the
/// resolution rules can be exercised against synthetic sources — a probe file
/// written into the real tree would be visible to every other test while it
/// runs, which is a race, not a test.
fn analyse_sources(sources: BTreeMap<String, String>) -> Vec<Site> {
    let prepared: BTreeMap<String, String> =
        sources.into_iter().map(|(k, v)| (k, prepare(&v))).collect();
    let idx = build_index(&prepared);
    let sinks = raw_sinks(&idx);
    let closure = mutator_closure(&idx, &sinks);
    all_sites(&idx, &closure)
}

fn analyse() -> Vec<Site> {
    let sources = production_sources();
    let idx = build_index(&sources);
    let sinks = raw_sinks(&idx);
    let closure = mutator_closure(&idx, &sinks);
    all_sites(&idx, &closure)
}

fn execution_sites(sites: &[Site]) -> BTreeMap<&str, usize> {
    let mut out: BTreeMap<&str, usize> = BTreeMap::new();
    for s in sites.iter().filter(|s| s.class == Class::Execution) {
        *out.entry(s.file.as_str()).or_default() += 1;
    }
    out
}

// ═══════════════════════════════════════════════════════════════════════════
// THE GUARDS
// ═══════════════════════════════════════════════════════════════════════════

/// No file grows its committed execution writes.
///
/// Per file, not one total: a subsystem that migrates must not silently fund a
/// new write somewhere else.
#[test]
fn no_file_grows_its_committed_execution_writes() {
    let ledger = execution_ledger();
    let sites = analyse();
    let actual = execution_sites(&sites);

    let mut grew = Vec::new();
    let mut shrank = Vec::new();
    for (file, &count) in &actual {
        match ledger.get(file) {
            Some(&allowed) if count > allowed => {
                grew.push(format!("  {file}: {allowed} allowed, {count} found"))
            }
            Some(&allowed) if count < allowed => {
                shrank.push(format!("  {file}: {allowed} allowed, {count} found"))
            }
            Some(_) => {}
            None => grew.push(format!(
                "  {file}: not on the ledger at all, {count} found"
            )),
        }
    }
    for (file, &allowed) in &ledger {
        if !actual.contains_key(file) {
            shrank.push(format!("  {file}: {allowed} allowed, 0 found"));
        }
    }

    assert!(
        grew.is_empty(),
        "these files gained committed writes reachable from block execution. A \
         block that is never accepted can now change canonical state in one more \
         place. Route the write through `ExecutionView`; do not raise the \
         ledger:\n{}",
        grew.join("\n")
    );
    assert!(
        shrank.is_empty(),
        "these files now have FEWER committed execution writes than recorded, \
         which is the goal — lower the ledger to lock the progress in:\n{}",
        shrank.join("\n")
    );
}

/// The number of application column families a block can still commit to.
#[test]
fn the_committed_column_family_count_does_not_grow() {
    let sites = analyse();
    let cfs: BTreeSet<&Cf> = sites
        .iter()
        .filter(|s| s.class == Class::Execution)
        .flat_map(|s| s.cfs.iter())
        .collect();
    assert!(
        cfs.len() <= LEDGER_CF_COUNT,
        "block execution can now commit to {} column families, up from {}. The \
         application journal has to cover every one of them.",
        cfs.len(),
        LEDGER_CF_COUNT
    );
    assert_eq!(
        cfs.len(),
        LEDGER_CF_COUNT,
        "fewer families are committed than recorded — lower LEDGER_CF_COUNT"
    );
}

/// Non-execution writes are classified, not ignored.
///
/// Each of these is a legitimate committed write, and each has a reason that
/// does not generalise. Pinning the counts means a new writer cannot arrive
/// wearing one of these labels without the number moving.
#[test]
fn non_execution_paths_are_classified() {
    /// `(class, sites, why it is not execution)`
    const EXPECTED: &[(Class, usize, &str)] = &[
        (Class::Genesis, 2, "no block exists to abandon: account prefunding and the empty archive snapshot"),
        (Class::ReorgUndo, 3, "the committed write that unwinds an already-published block"),
        (Class::ChainStorage, 16, "blocks, transactions, receipts, their indexes, validator sets, pruning — not application state"),
        (Class::Snapshot, 1, "fast-sync restore, outside consensus"),
        (Class::OperatorTooling, 7, "see operator_tooling_writes_are_declared_deployment_blockers"),
    ];
    let sites = analyse();
    let mut counted: BTreeMap<Class, usize> = BTreeMap::new();
    for s in &sites {
        *counted.entry(s.class).or_default() += 1;
    }
    for (class, expected, why) in EXPECTED {
        let found = counted.get(class).copied().unwrap_or(0);
        assert_eq!(
            found, *expected,
            "{class:?} now has {found} committed write sites, recorded {expected}.\n  \
             this class is excluded from the execution ledger because: {why}"
        );
    }
    let unexpected: Vec<_> = counted
        .keys()
        .filter(|c| {
            **c != Class::Execution && !EXPECTED.iter().any(|(e, _, _)| e == *c)
        })
        .collect();
    assert!(
        unexpected.is_empty(),
        "these write classes are not declared: {unexpected:?}"
    );
}

/// Every dispatcher arm is declared, with where it writes.
///
/// The executor's `TxPayload` match is the entire transaction surface. A new arm
/// arrives with a new write surface, and this fails until someone says which
/// kind it is — so "we forgot to check the new transaction family" cannot
/// happen quietly.
#[test]
fn every_dispatcher_arm_is_declared() {
    let root = workspace_root();
    let src = std::fs::read_to_string(root.join("crates/state/src/executor.rs"))
        .expect("read executor.rs");
    let production = prepare(&src);

    let mut found: BTreeSet<String> = BTreeSet::new();
    let b = production.as_bytes();
    let mut i = 0usize;
    while let Some(rel) = production[i..].find("TxPayload::") {
        let at = i + rel + "TxPayload::".len();
        i = at;
        if let Some((name, _)) = ident_at(b, at) {
            found.insert(name);
        }
    }

    let declared: BTreeSet<String> = ARMS.iter().map(|(n, _, _)| n.to_string()).collect();
    let missing: Vec<_> = found.difference(&declared).collect();
    let stale: Vec<_> = declared.difference(&found).collect();

    assert!(
        missing.is_empty(),
        "the executor dispatches transaction families that are not declared \
         here: {missing:?}. Add each to ARMS saying whether it writes through \
         the overlay, commits, or both — an undeclared arm is an unmeasured \
         write surface."
    );
    assert!(
        stale.is_empty(),
        "ARMS lists families the executor no longer dispatches: {stale:?}"
    );

    let overlay = ARMS.iter().filter(|(_, k, _)| *k == ArmKind::Overlay).count();
    let committed = ARMS.iter().filter(|(_, k, _)| *k == ArmKind::Committed).count();
    let mixed = ARMS.iter().filter(|(_, k, _)| *k == ArmKind::Mixed).count();
    assert_eq!(
        (overlay, committed, mixed),
        (12, 17, 1),
        "the overlay/committed/mixed split changed. Moving an arm from \
         Committed to Overlay is progress — update this and the ledger \
         together; any other movement is not."
    );
    assert_eq!(ARMS.len(), 30, "arm count changed");
}

/// The account write is universal: even the overlay-only arms commit one.
///
/// Every arm's fee and nonce path debits the sender and credits the proposer
/// through `StateManager::put_account`, which writes `cf::STATE` immediately.
/// "Twelve arms are overlay-only" is therefore true of each subsystem's OWN
/// rows and false of the account row underneath all of them — which is why
/// accounts migrate first, and why this is stated where the arm split is, not
/// somewhere a reader has to go looking for it.
#[test]
fn the_account_write_is_universal_even_on_overlay_only_arms() {
    let sources = production_sources();
    let ledger = execution_ledger();
    assert!(
        ledger.contains_key("crates/state/src/state.rs"),
        "the account write must be on the ledger: {ACCOUNT_WRITE_IS_UNIVERSAL}"
    );

    // Two subsystems whose own rows are fully on the overlay, and which still
    // call `put_account` for the fee.
    for overlay_only in [
        "crates/state/src/node_registry.rs",
        "crates/state/src/storage_metadata.rs",
    ] {
        let src = sources
            .get(overlay_only)
            .unwrap_or_else(|| panic!("{overlay_only} is not in the source map"));
        assert!(
            src.contains("put_account("),
            "{overlay_only} is listed as overlay-only, which is true of its own \
             rows — but it debits an account through {ACCOUNT_WRITE_IS_UNIVERSAL}, \
             and this test exists so that stays visible. If the account write \
             really is gone, this is progress: update the claim."
        );
        assert!(
            !ledger.contains_key(overlay_only),
            "{overlay_only} now has committed writes of its own"
        );
    }
}

/// Dead column families stay out of the ledger and out of the journal.
#[test]
fn dead_column_families_are_written_by_nothing() {
    let sources = production_sources();
    for dead in DEAD_COLUMN_FAMILIES {
        let mut seen_outside_registry = Vec::new();
        for (file, src) in &sources {
            if file == "crates/storage/src/db.rs" {
                continue;
            }
            if named_cfs(src).contains(*dead) {
                seen_outside_registry.push(file.as_str());
            }
        }
        assert!(
            seen_outside_registry.is_empty(),
            "cf::{dead} is recorded as dead schema but is referenced in \
             {seen_outside_registry:?}. Either it is alive — remove it from \
             DEAD_COLUMN_FAMILIES and account for its writes — or the \
             reference is a mistake. It must not enter the journal allowlist \
             while it is dead."
        );
    }
}

/// The operator import that changes application state outside consensus.
///
/// `node/src/main.rs` carries a recovery command that writes messaging public
/// keys straight into the database, with a comment naming the divergence it
/// exists to repair. It is not execution, not genesis, and not chain storage:
/// it is a human changing consensus-relevant state with no block, no candidate
/// and no journal, on one node.
///
/// That makes it a deployment blocker in its own right, independent of the
/// journal work — a node that runs it diverges from every node that did not.
/// This test pins it so it cannot be quietly reclassified as routine tooling.
#[test]
fn operator_tooling_writes_are_declared_deployment_blockers() {
    let sites = analyse();
    let operator: Vec<&Site> = sites
        .iter()
        .filter(|s| s.class == Class::OperatorTooling)
        .collect();
    assert!(
        !operator.is_empty(),
        "the operator-tooling write disappeared. If it was removed, delete this \
         test and the deployment blocker with it."
    );
    let families: BTreeSet<&Cf> = operator.iter().flat_map(|s| s.cfs.iter()).collect();
    let messaging = families
        .iter()
        .any(|c| matches!(c, Cf::Named(n) if n.starts_with("MESSAGING_")));
    assert!(
        messaging,
        "the operator recovery path no longer writes a MESSAGING_* family. \
         Update this test to name what it writes now; do not delete it."
    );
    for s in &operator {
        assert_eq!(
            s.file, "crates/node/src/main.rs",
            "a second operator-tooling writer appeared at {}:{}. Every one of \
             these changes application state outside consensus and blocks \
             deployment.",
            s.file, s.line
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ANALYSER SELF-TESTS
// ═══════════════════════════════════════════════════════════════════════════
//
// A ledger is only worth its resolution rules. Each test below was written by
// BREAKING the rule it covers and watching the count fall to zero — the shapes
// here are the ones that would otherwise let a committed write hide, and the
// first four are the shapes that made 317 sites invisible to a check that knew
// only `db.put`.

/// A minimal storage library: one store type whose `put` writes a family.
fn fake_library() -> (String, String) {
    (
        "crates/storage/src/schema.rs".to_string(),
        r#"
pub struct StateStore<'a> { db: &'a Database }
impl<'a> StateStore<'a> {
    pub fn new(db: &'a Database) -> Self { Self { db } }
    pub fn put_account(&self, k: &[u8], v: &[u8]) -> Result<()> {
        self.db.put(cf::STATE, k, v)
    }
}
"#
        .to_string(),
    )
}

fn sources_with(caller: &str) -> BTreeMap<String, String> {
    let (lib_path, lib) = fake_library();
    BTreeMap::from([
        (lib_path, lib),
        ("crates/state/src/probe_executor.rs".to_string(), caller.to_string()),
    ])
}

fn execution_count(caller: &str) -> usize {
    analyse_sources(sources_with(caller))
        .iter()
        .filter(|s| s.class == Class::Execution)
        .count()
}

#[test]
fn the_analyser_sees_a_plain_store_call() {
    assert_eq!(
        execution_count(
            r#"
impl Probe {
    fn execute(&self, db: &Database) -> Result<()> {
        let store = StateStore::new(db);
        store.put_account(b"k", b"v")
    }
}
"#
        ),
        1
    );
}

/// A write moved behind a private helper is still counted.
///
/// This is the shape the raw-syntax guard cannot follow at all. `put_account`
/// below contains no database call: the write lives one level down, in a
/// private helper the caller has never heard of. Without the transitive
/// closure, `put_account` is not a mutator, the caller is not a site, and a
/// subsystem could zero its ledger entry by adding one indirection.
#[test]
fn a_write_behind_a_helper_is_still_counted() {
    let library_with_helper = r#"
pub struct StateStore<'a> { db: &'a Database }
impl<'a> StateStore<'a> {
    pub fn new(db: &'a Database) -> Self { Self { db } }
    pub fn put_account(&self, k: &[u8], v: &[u8]) -> Result<()> {
        self.persist(k, v)
    }
    fn persist(&self, k: &[u8], v: &[u8]) -> Result<()> {
        self.db.put(cf::STATE, k, v)
    }
}
"#;
    let sources = BTreeMap::from([
        ("crates/storage/src/schema.rs".to_string(), library_with_helper.to_string()),
        (
            "crates/state/src/probe_executor.rs".to_string(),
            r#"
impl Probe {
    fn execute(&self, db: &Database) -> Result<()> {
        let store = StateStore::new(db);
        store.put_account(b"k", b"v")
    }
}
"#
            .to_string(),
        ),
    ]);
    assert_eq!(
        analyse_sources(sources)
            .iter()
            .filter(|s| s.class == Class::Execution)
            .count(),
        1,
        "a write one level down a private helper must still make its caller a site"
    );
}

/// Renaming the receiver does not hide the write.
///
/// The raw-syntax guard next door matches the literal text `db.put(`. Rename the
/// field to `database` and its count silently drops; this resolves the receiver
/// by TYPE, so the rename changes nothing.
#[test]
fn a_renamed_receiver_is_still_counted() {
    let (_, _) = fake_library();
    let renamed_library = r#"
pub struct StateStore<'a> { database: &'a Database }
impl<'a> StateStore<'a> {
    pub fn new(database: &'a Database) -> Self { Self { database } }
    pub fn put_account(&self, k: &[u8], v: &[u8]) -> Result<()> {
        self.database.put(cf::STATE, k, v)
    }
}
"#;
    let sources = BTreeMap::from([
        ("crates/storage/src/schema.rs".to_string(), renamed_library.to_string()),
        (
            "crates/state/src/probe_executor.rs".to_string(),
            r#"
impl Probe {
    fn execute(&self, db: &Database) -> Result<()> {
        let store = StateStore::new(db);
        store.put_account(b"k", b"v")
    }
}
"#
            .to_string(),
        ),
    ]);
    let n = analyse_sources(sources)
        .iter()
        .filter(|s| s.class == Class::Execution)
        .count();
    assert_eq!(n, 1, "renaming the database receiver must not hide the write");
}

/// A call split across lines is still one call.
///
/// `self.db\n    .put(..)` is the commonest shape in this codebase, and the
/// first version of the raw-syntax guard was blind to it — rustfmt decided
/// whether a write counted.
#[test]
fn a_multiline_call_is_still_counted() {
    let multiline_library = r#"
pub struct StateStore<'a> { db: &'a Database }
impl<'a> StateStore<'a> {
    pub fn new(db: &'a Database) -> Self { Self { db } }
    pub fn put_account(&self, k: &[u8], v: &[u8]) -> Result<()> {
        self.db
            .put(
                cf::STATE,
                k,
                v,
            )
    }
}
"#;
    let sources = BTreeMap::from([
        ("crates/storage/src/schema.rs".to_string(), multiline_library.to_string()),
        (
            "crates/state/src/probe_executor.rs".to_string(),
            r#"
impl Probe {
    fn execute(&self, db: &Database) -> Result<()> {
        let store = StateStore::new(db);
        store
            .put_account(
                b"k",
                b"v",
            )
    }
}
"#
            .to_string(),
        ),
    ]);
    let sites = analyse_sources(sources);
    assert_eq!(
        sites.iter().filter(|s| s.class == Class::Execution).count(),
        1,
        "a line break between the receiver and the method must not hide the call"
    );
}

/// A write whose column family comes from a runtime binding is counted, and
/// named.
///
/// `execute_accept_assignment_v2` was exactly this: `db.put(cf, ..)` where `cf`
/// was chosen by an `if` between two families. No name-based check could see
/// which family it wrote, and a check that gave up would have dropped the write
/// entirely.
#[test]
fn a_variable_column_family_is_counted_and_attributed() {
    let variable_cf_library = r#"
pub struct BitmapStore<'a> { db: &'a Database }
impl<'a> BitmapStore<'a> {
    pub fn new(db: &'a Database) -> Self { Self { db } }
    pub fn stage(&self, epoch_zero: bool, k: &[u8], v: &[u8]) -> Result<()> {
        let cf = if epoch_zero { cf::ATTESTATIONS } else { cf::ATTESTATIONS_EPOCH };
        self.db.put(cf, k, v)
    }
}
"#;
    let sources = BTreeMap::from([
        ("crates/storage/src/schema.rs".to_string(), variable_cf_library.to_string()),
        (
            "crates/state/src/probe_executor.rs".to_string(),
            r#"
impl Probe {
    fn execute(&self, db: &Database) -> Result<()> {
        let store = BitmapStore::new(db);
        store.stage(true, b"k", b"v")
    }
}
"#
            .to_string(),
        ),
    ]);
    let sites = analyse_sources(sources);
    let exec: Vec<&Site> = sites.iter().filter(|s| s.class == Class::Execution).collect();
    assert_eq!(exec.len(), 1, "a runtime-chosen family must not drop the write");
    assert_eq!(
        exec[0].cfs,
        BTreeSet::from([
            Cf::Named("ATTESTATIONS".to_string()),
            Cf::Named("ATTESTATIONS_EPOCH".to_string())
        ]),
        "both candidate families must be attributed — over-attribution is the \
         safe direction when the family is not decidable from the source"
    );
}

/// A family named nowhere at all still counts as a write, as [`Cf::Variable`].
#[test]
fn an_unnameable_column_family_is_still_a_write() {
    let opaque_library = r#"
pub struct OpaqueStore<'a> { db: &'a Database }
impl<'a> OpaqueStore<'a> {
    pub fn new(db: &'a Database) -> Self { Self { db } }
    pub fn stage(&self, family: &str, k: &[u8], v: &[u8]) -> Result<()> {
        self.db.put(family, k, v)
    }
}
"#;
    let sources = BTreeMap::from([
        ("crates/storage/src/schema.rs".to_string(), opaque_library.to_string()),
        (
            "crates/state/src/probe_executor.rs".to_string(),
            r#"
impl Probe {
    fn execute(&self, db: &Database) -> Result<()> {
        OpaqueStore::new(db).stage("anything", b"k", b"v")
    }
}
"#
            .to_string(),
        ),
    ]);
    let sites = analyse_sources(sources);
    let exec: Vec<&Site> = sites.iter().filter(|s| s.class == Class::Execution).collect();
    assert_eq!(exec.len(), 1);
    assert_eq!(exec[0].cfs, BTreeSet::from([Cf::Variable]));
}

/// An accessor hop is followed: `store.identity_roots().put(..)`.
///
/// Eleven of the seventeen ledger files reach their writes this way. A resolver
/// that stopped at the first `.` would report zero for all of them.
#[test]
fn an_accessor_hop_is_followed() {
    let faceted_library = r#"
pub struct IdentityRootStore<'a> { db: &'a Database }
impl<'a> IdentityRootStore<'a> {
    pub fn new(db: &'a Database) -> Self { Self { db } }
    pub fn put(&self, k: &[u8], v: &[u8]) -> Result<()> { self.db.put(cf::IDENTITY, k, v) }
}
pub struct DocClassStore<'a> { db: &'a Database }
impl<'a> DocClassStore<'a> {
    pub fn new(db: &'a Database) -> Self { Self { db } }
    pub fn identity_roots(&self) -> IdentityRootStore<'_> { IdentityRootStore::new(self.db) }
}
"#;
    let sources = BTreeMap::from([
        ("crates/storage/src/docclass_store.rs".to_string(), faceted_library.to_string()),
        (
            "crates/state/src/probe_executor.rs".to_string(),
            r#"
impl Probe {
    fn execute(&self, db: &Database) -> Result<()> {
        let store = DocClassStore::new(db);
        store.identity_roots().put(b"k", b"v")
    }
}
"#
            .to_string(),
        ),
    ]);
    let sites = analyse_sources(sources);
    let exec: Vec<&Site> = sites.iter().filter(|s| s.class == Class::Execution).collect();
    assert_eq!(exec.len(), 1, "the accessor hop must be followed");
    assert_eq!(exec[0].cfs, BTreeSet::from([Cf::Named("IDENTITY".to_string())]));
}

/// A store reached through a struct field, not a local binding.
#[test]
fn a_store_held_in_a_field_is_counted() {
    assert_eq!(
        analyse_sources(BTreeMap::from([
            fake_library(),
            (
                "crates/state/src/probe_executor.rs".to_string(),
                r#"
pub struct Probe { db: Arc<Database> }
impl Probe {
    fn execute(&self) -> Result<()> {
        StateStore::new(&self.db).put_account(b"k", b"v")
    }
}
"#
                .to_string()
            ),
        ]))
        .iter()
        .filter(|s| s.class == Class::Execution)
        .count(),
        1
    );
}

/// A write inside a `#[cfg(test)]` module is not block execution.
#[test]
fn a_cfg_test_module_is_not_counted() {
    assert_eq!(
        execution_count(
            r#"
#[cfg(test)]
mod tests {
    fn fixture(db: &Database) -> Result<()> {
        let store = StateStore::new(db);
        store.put_account(b"k", b"v")
    }
}
"#
        ),
        0,
        "a fixture cannot be reached from a block"
    );
}

/// Publishing a candidate is not an execution violation.
///
/// The overlay does end in a real `WriteBatch` — `into_batch` puts every
/// buffered row and commits — but that batch is reachable only from
/// `AcceptedCandidate::publish`, which is the ONE sanctioned committed write.
/// Counting it here would mark the sanctioned publisher as the violation and
/// every migrated subsystem as unmigrated: the exact inverse of what this
/// ledger measures.
#[test]
fn publishing_a_candidate_is_not_a_committed_execution_write() {
    let overlay = r#"
pub struct ApplicationOverlay<'a> { db: &'a Database }
impl<'a> ApplicationOverlay<'a> {
    pub fn new(db: &'a Database) -> Self { Self { db } }
    pub fn put(&mut self, cf: &str, k: &[u8], v: &[u8]) -> Result<()> { Ok(()) }
    pub fn publish(self, k: &[u8], v: &[u8]) -> Result<()> {
        let mut batch = self.db.batch();
        batch.put(cf::STATE, k, v)?;
        batch.commit()
    }
}
"#;
    let caller = r#"
impl Probe {
    fn execute(&self, db: &Database) -> Result<()> {
        let mut overlay = ApplicationOverlay::new(db);
        overlay.put(cf::STATE, b"k", b"v")?;
        overlay.publish(b"k", b"v")
    }
}
"#;
    // As it stands: the overlay file is excluded, so neither line is a site.
    let excluded = analyse_sources(BTreeMap::from([
        ("crates/storage/src/overlay.rs".to_string(), overlay.to_string()),
        ("crates/state/src/probe_executor.rs".to_string(), caller.to_string()),
    ]));
    assert_eq!(
        excluded.iter().filter(|s| s.class == Class::Execution).count(),
        0,
        "staging into the overlay, and publishing it, are the migration target"
    );

    // The same sources with the overlay living somewhere the exclusion does not
    // cover: now the publish IS counted. That is what the exclusion is for, and
    // this half is why it is not inert.
    let not_excluded = analyse_sources(BTreeMap::from([
        ("crates/storage/src/some_other_store.rs".to_string(), overlay.to_string()),
        ("crates/state/src/probe_executor.rs".to_string(), caller.to_string()),
    ]));
    assert_eq!(
        not_excluded.iter().filter(|s| s.class == Class::Execution).count(),
        1,
        "without the exclusion the publish reads as a committed execution write"
    );
}

/// Genesis, reorg-undo and chain storage are classified away from execution —
/// and a write in an execution function in the same file still counts.
#[test]
fn classification_separates_paths_within_one_file() {
    let sources = BTreeMap::from([
        fake_library(),
        (
            "crates/state/src/state.rs".to_string(),
            r#"
impl StateManager {
    pub fn init_from_genesis(&self, db: &Database) -> Result<()> {
        StateStore::new(db).put_account(b"k", b"v")
    }
    pub fn revert_block_state_diffs(&self, db: &Database) -> Result<()> {
        StateStore::new(db).put_account(b"k", b"v")
    }
    pub fn put_account(&self, db: &Database) -> Result<()> {
        StateStore::new(db).put_account(b"k", b"v")
    }
}
"#
            .to_string(),
        ),
    ]);
    let sites = analyse_sources(sources);
    let by_class = |c: Class| sites.iter().filter(|s| s.class == c).count();
    assert_eq!(by_class(Class::Genesis), 1);
    assert_eq!(by_class(Class::ReorgUndo), 1);
    assert_eq!(
        by_class(Class::Execution),
        1,
        "three writes in one file, three different classes"
    );
}
