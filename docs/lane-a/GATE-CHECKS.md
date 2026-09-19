# The gate checks the final gate did not run

The final gate for this lane ran `cargo test --workspace` and nothing else. Four
checks that belong in a release gate were omitted. This file runs them and
records what they found.

Every command below was run from the lane worktree with
`CARGO_INCREMENTAL=0` and an explicit `CARGO_TARGET_DIR`. Where a check needs a
comparison against the lane's base, the base is commit **4c105d8** in a separate
detached worktree, built in its own freshly created target directory.

- Tree under test: branch `lane-b/trk-c-evidence`
- Base for comparison: `4c105d8 node: validate activation before the watermark, through one shared entry point`

---

## 1. Workspace clippy, by warning IDENTITY

### Why identity and not count

A count is not a check. A run that removes four warnings and adds four warnings
has the same count and a different meaning. The identity used here is the triple

```
(file, lint code, message text)
```

and the comparison is over the SET of those triples, plus a separate report of
shared identities whose occurrence count moved. Occurrence counts are reported
but never used to decide whether something is new.

### Method

Both runs used `--keep-going`, which is not optional here: see §1.2.

```
rm -rf <clippy-dir> && mkdir -p <clippy-dir>
CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=<clippy-dir> \
  cargo clippy --workspace --all-targets --keep-going --message-format=json
```

run once in the lane worktree and once in the base worktree, each into a
freshly created and then deleted target directory. The JSON streams were
reduced to identities by a small script (kept in the scratchpad, not the repo),
which drops the per-crate `"<crate> generated N warnings"` rollup lines because
those are summaries rather than identities.

### 1.1 Result

```
BASE 4c105d8 : 275 distinct identities, 1825 occurrences
HEAD         : 277 distinct identities, 1849 occurrences

=== NEW identities (present at HEAD, absent at base): 2 ===
  [clippy::doc_overindented_list_items] scripts/src/setup_local_testnet.rs
      doc list item overindented   (x18)
  [clippy::uninlined_format_args] scripts/src/setup_local_testnet.rs
      variables can be used directly in the `format!` string   (x10)

=== REMOVED identities (present at base, absent at HEAD): 0 ===

=== SHARED identities whose occurrence count changed: 2 ===
  [clippy::uninlined_format_args] crates/node/src/main.rs
      variables can be used directly in the `format!` string   base x130 -> head x124
  [clippy::uninlined_format_args] crates/state/src/nft_executor.rs
      variables can be used directly in the `format!` string   base x18 -> head x20
```

Clippy's exit status at HEAD is **0**. No lint is denied in this workspace, so
this is a warning inventory rather than a pass/fail, and it is reported as one.

### 1.2 The base does not compile under `--all-targets`

The base clippy run exited **101**:

```
error: could not compile `sumchain-scripts` (bin "setup-local-testnet" test) due to 1 previous error
error: could not compile `sumchain-scripts` (bin "setup-local-testnet") due to 1 previous error
```

From the JSON stream, the only two diagnostics attributed to that file at base
are both this error and nothing else:

```
error E0063 | missing field `account_root_enabled_from_height` in initializer of `sumchain_genesis::ChainParams`
error E0063 | missing field `account_root_enabled_from_height` in initializer of `sumchain_genesis::ChainParams`
total messages for setup_local_testnet.rs at base: 2
```

This is why `--keep-going` was specified in the brief and why the comparison is
still meaningful: without it the base run would have stopped and produced no
inventory at all.

**Both "NEW" identities are an artefact of that failure, not a regression.** At
base the file could not be linted, so it contributed zero warnings; the lane
made it compile again in

```
1e40353 scripts: give the local testnet the activation field that has not compiled since fd7bb8b
```

and its 28 pre-existing style warnings became visible for the first time. They
are stylistic (`uninlined_format_args`, `doc_overindented_list_items`), they are
in a local-testnet helper binary, and no line of that file was authored by this
lane other than the one field added by `1e40353`. Left alone deliberately:
reformatting 28 lines of an untouched helper to make an inventory look tidier
would be churn, and this document would then have to explain the churn instead
of the fact.

### 1.3 Identities this pass DID close

The first run of this comparison found **five** new identities. Three were
genuinely introduced by this lane, in files this lane authored, and were closed
rather than reported:

| identity | site | disposition |
|---|---|---|
| `clippy::field_reassign_with_default` (x2) | `crates/genesis/tests/activation_digest.rs` | rewritten as `ChainParams { .., ..ChainParams::default() }` struct-update literals |
| `clippy::type_complexity` | `crates/genesis/tests/activation_digest.rs:525` | `&[(&str, &dyn Fn(&mut ChainParams, u64))]` factored into a `type GateCase<'a>` alias |
| `clippy::unnecessary_to_owned` | `crates/consensus/tests/admission_and_archival.rs:517` | `changed.contains(&cf::BLOCKS.to_string())` became `changed.iter().any(\|c\| *c == cf::BLOCKS)` |

Both suites were re-run afterwards:

```
cargo test -p sumchain-genesis --test activation_digest
test result: ok. 17 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

cargo test -p sumchain-consensus --test admission_and_archival
test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

and clippy was re-run from a fresh directory to produce the §1.1 inventory. The
five-identity result is recorded here rather than erased, because "we found five
and closed three" is the honest statement and "there were two" is not.

### 1.4 The two moved occurrence counts

Neither is a new identity; both are existing `uninlined_format_args` sites whose
count changed because the lane added or removed `format!` calls in files that
already had the lint. `crates/node/src/main.rs` went down by 6, and
`crates/state/src/nft_executor.rs` up by 2. No action; recorded so that a future
comparison that sees them move again knows they were already moving.

---

## 2. The isolated compile probe, proven in isolation

### What is being proven

`crates/storage/tests/candidate_compile_fail.rs` asserts that certain misuses of
the candidate/publication API are **compile** errors, by shelling out to `rustc`
and compiling probe programs against the workspace's own rlibs. That harness has
a specific way to fail silently: if it cannot find a usable rlib, every negative
test passes because everything fails to compile, for the wrong reason.

The harness has two defences, both of which are only meaningful if they actually
work under a non-default `CARGO_TARGET_DIR`:

- `deps_dir()` derives the rlib search path from **this test binary's own path**
  (`std::env::current_exe()`), not from `CARGO_MANIFEST_DIR`. The file's own
  comment records that the previous version hardcoded
  `<manifest>/../../target/debug/deps` and therefore pointed at an unrelated
  tree under any isolated target dir — "Every gate that isolates its target
  directory ... tripped over it."
- `working_rlib()` tries candidate rlibs newest-first and keeps only one that
  can compile the positive control `CONTROL`, so a stale rlib built by a
  different rustc (`E0514`) cannot be mistaken for an API rejection. `rejected()`
  additionally asserts `E0514` never reaches a negative test.

### Method and result

The run below used the lane's isolated target directory, not `./target` — which
does not exist in this worktree at all:

```
$ ls -d ./target
ls: ./target: No such file or directory
```

Rlibs visible in the isolated deps directory at the time of the run:

```
$ ls <tgt>/debug/deps/libsumchain_storage-*.rlib | wc -l
       3
<tgt>/debug/deps/libsumchain_storage-4c6814594f9bd92a.rlib
<tgt>/debug/deps/libsumchain_storage-c89150cd0ac07989.rlib
<tgt>/debug/deps/libsumchain_storage-fc7dace365464a21.rlib

$ ls <tgt>/debug/deps/*.rlib | wc -l
     662
```

Three candidate `sumchain_storage` rlibs is the interesting number: it is
exactly the situation `working_rlib()` exists for — the harness must pick the one
that compiles the control, not the newest.

```
$ CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=<tgt> \
    cargo test -p sumchain-storage --test candidate_compile_fail

running 11 tests
test a_transition_cannot_be_built_with_fields_missing ... ok
test the_overlay_cannot_be_published_directly_from_outside_the_crate ... ok
test publication_takes_no_artifacts ... ok
test an_execution_view_cannot_publish ... ok
test publishing_without_verifying_does_not_compile ... ok
test a_canonical_transition_cannot_be_constructed_from_independent_artifacts ... ok
test the_probe_harness_accepts_valid_code ... ok
test the_two_operand_comparison_does_not_exist ... ok
test bound_artifacts_cannot_be_replaced_on_an_executed_candidate ... ok
test a_block_execution_cannot_be_built_or_destructured_externally ... ok
test acceptance_cannot_be_handed_a_root ... ok

test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.93s
```

`the_probe_harness_accepts_valid_code` is the positive control. It passed under
the isolated target directory, alongside 662 rlibs and 3 candidates, which is
the thing that needed proving: the ten negative tests are rejections by the API,
not by a broken search path.

**What this does NOT prove.** It proves the harness works in *this* isolated
directory. It does not prove the harness survives an environment with **no**
`sumchain_storage` rlib — in that case `working_rlib()` panics with a message
telling the caller to build first, which is the correct behaviour but is not
exercised here.

---

## 3. The seven ignored tests

### The list, exactly

```
$ CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=<tgt> cargo test --workspace -- --ignored --list

     Running tests/execution_closure.rs (…/deps/execution_closure-339a12f1eff71083)
dump_manifest: test
   Doc-tests sumc_sdk
crates/sumc-sdk/src/lib.rs - (line 7): test
   Doc-tests sumc_sdk_macros
crates/sumc-sdk-macros/src/lib.rs - call (line 84): test
crates/sumc-sdk-macros/src/lib.rs - contract (line 18): test
crates/sumc-sdk-macros/src/lib.rs - init (line 57): test
crates/sumc-sdk-macros/src/lib.rs - payable (line 139): test
crates/sumc-sdk-macros/src/lib.rs - view (line 114): test
```

Seven. **Six of them are not `#[ignore]` at all** — they are documentation code
blocks fenced ```` ```ignore ```` / ```` ```rust,ignore ````, which rustdoc
reports through the same `--ignored` channel. That distinction matters for the
disposition, so it is made per row rather than glossed.

### Disposition, per test

| # | File | Test | Kind | Why it is ignored | Should it be? | What covers the behaviour instead |
|---|---|---|---|---|---|---|
| 1 | `crates/state/tests/execution_closure.rs:1660` | `dump_manifest` | real `#[ignore]`, with reason string `"reporting aid: run with --ignored to regenerate MANIFEST"` | It is a generator, not an assertion. Its whole body is `println!`/`eprintln!` of the committed-write manifest rows so a human can paste them into `MANIFEST`. It can never fail. | **Yes.** A test with no assertion that runs in the default gate is noise that costs time and proves nothing. | `the_committed_write_manifest_is_exact` (same file, line 1701) runs in the default gate and asserts the manifest against the tree three ways: a row the manifest lacks, a row the tree lacks, and a row whose occurrence count moved. `unreached_mutators_are_declared` and `the_committed_column_family_count_does_not_grow` sit beside it. |
| 2 | `crates/sumc-sdk/src/lib.rs:7` | crate-level doc example | ```` ```rust,ignore ```` | The example uses `#[sumc_contract]` / `#[sumc_methods]` on a type with `Map<Address, u128>` fields; compiling it as a doctest would require the macro to expand to real WASM exports inside the doctest harness. | **Yes**, but see the caveat below. | Nothing. This is documentation, not coverage. |
| 3 | `crates/sumc-sdk-macros/src/lib.rs:18` | `contract` doc example | ```` ```ignore ```` | Same: a proc-macro crate cannot use its own macros in its own doctests. | Yes | Nothing |
| 4 | `crates/sumc-sdk-macros/src/lib.rs:57` | `init` doc example | ```` ```ignore ```` | as above | Yes | Nothing |
| 5 | `crates/sumc-sdk-macros/src/lib.rs:84` | `call` doc example | ```` ```ignore ```` | as above | Yes | Nothing |
| 6 | `crates/sumc-sdk-macros/src/lib.rs:114` | `view` doc example | ```` ```ignore ```` | as above | Yes | Nothing |
| 7 | `crates/sumc-sdk-macros/src/lib.rs:139` | `payable` doc example | ```` ```ignore ```` | as above | Yes | Nothing |

### Verification that #1 is a reporting aid and its guard is live

```
$ cargo test -p sumchain-state --test execution_closure -- --ignored dump_manifest
running 1 test
test dump_manifest ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 25 filtered out; finished in 1.00s

$ cargo test -p sumchain-state --test execution_closure -- the_committed_write_manifest_is_exact
running 1 test
test the_committed_write_manifest_is_exact ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 25 filtered out; finished in 0.97s
```

### Two things this list does not tell you

**A caveat on rows 2–7 that the "should it be?" column above is too generous
about.** Six ```` ```ignore ```` blocks mean the SDK's five public macros and its
front-page example are documented by code that is never compiled. They can drift
from the macros they document and nothing will say so. That is a real, if
low-severity, documentation-rot exposure, and calling it "correctly ignored"
without saying that would be the kind of confident sentence this evidence pass
exists to avoid. The cheap improvement is `compile_fail`-free `no_run` doctests
in a downstream test crate that depends on `sumc-sdk`; that is a change, not
evidence, so it is named here and not made.

**There is an eighth `#[ignore]` in the repository that this command cannot
see.**

```
tools/b0-pre-validator/tests/authentic_stage2_graphs.rs:262
#[ignore = "run explicitly with B0PRE_METADATA_DIR set to the preserved authentic metadata"]
fn regenerate()
```

`tools/b0-pre-validator` is deliberately outside the workspace — `Cargo.toml`
carries the comment "B0-PRE (#123) host-side reproducibility tooling lives
outside the workspace so it has zero dependency edges into production crates" —
so `cargo test --workspace` never reaches it. It is the same shape as
`dump_manifest`: a regenerator, correctly ignored, requiring an environment
variable pointing at preserved authentic metadata that is not present on this
machine. Recorded so that "seven" is not mistaken for "all of them".

---

## 4. Mutation anchor and residue audit

### Scope: how many mutation runs this lane actually records

The lane is 43 commits (`4c105d8..HEAD`). Searching every commit message body
for `mutat`, `kill`, `anchor`, `byte-identical`, `sha256`, `revert`, `flip`,
`negative control`, `made .* return`, `deleting the`:

Exactly **one** commit records a mutation run with anchors:

```
6e64dd5 node, genesis: refuse a gate this binary invented on a database that predates it
```

Its claim:

> Two mutations, both killed, both files restored byte-identical (pre and post
> sha256 equal):
>
>  * deleting the check from `node.rs` makes the named source test run and fail
>    on "a first start must check for retroactively opened gates" -- a failure,
>    not a compile error;
>  * making `retroactive_gates_on_a_first_start` return empty makes the genesis
>    suite compile, run 17 and fail 1:
>    `a_newly_introduced_gate_below_the_head_refuses_a_first_start`.

Other commits in the lane mention mutation *batteries* (`docs/lane-a/*-MUTATION-BATTERY.md`)
but none of those documents was added or modified in this lane
(`git diff --name-only 4c105d8..HEAD -- 'docs/*MUTATION*'` is empty), so they are
not this lane's runs and are out of scope for this audit.

### Anchor occurrence audit

Each anchor must occur exactly once in the tree.

```
$ grep -rn --include='*.rs' --include='*.md' -F "<anchor>" .
```

| # | Anchor | Occurrences | Where |
|---|---|---|---|
| A1 | `a first start must check for retroactively opened gates` | **1** | `crates/state/tests/runtime_activation.rs:199` |
| A2 | `a_first_start_refuses_before_it_records_what_it_refused` | **1** | `crates/state/tests/runtime_activation.rs:184` |
| A3 | `a_newly_introduced_gate_below_the_head_refuses_a_first_start` | **1** | `crates/genesis/tests/activation_digest.rs:525` |
| A4 | `fn retroactive_gates_on_a_first_start` | **1** | `crates/genesis/src/lib.rs:2025` |

All four: exactly once. No anchor has been duplicated, renamed, or split.

Note on A1, for anyone re-running this: the mutation was applied to
`crates/node/src/node.rs`, but the anchor string lives in the STATE test suite,
`crates/state/tests/runtime_activation.rs:199` — that is the "named source test"
the commit refers to, named in full two paragraphs earlier in the same message.
An auditor grepping `node.rs` for the anchor finds nothing and could wrongly
conclude it had been lost. It has not; it was never there.

### Residue audit

A mutation leaves residue if the mutated form survives anywhere in the tree.

**Mutation 1 — the check deleted from `node.rs`.** The call is present:

```
$ grep -rn 'retroactive_gates_on_a_first_start' crates/node/src/
crates/node/src/node.rs:431:                .retroactive_gates_on_a_first_start(current_height);
```

One call site, in `node.rs`, as before the mutation. No residue.

**Mutation 2 — `retroactive_gates_on_a_first_start` made to return empty.** The
function computes:

```rust
pub fn retroactive_gates_on_a_first_start(&self, current_height: u64) -> Vec<ActivationChange> {
    if current_height == 0 {
        return Vec::new();
    }
    self.activation_heights()
        .into_iter()
        .filter(|(gate, _)| !GATES_PREDATING_ACTIVATION_RECORDING.contains(gate))
        .filter_map(|(gate, height)| match height {
            Some(h) if h <= current_height => Some(ActivationChange::RetroactivelyOpened {
                gate: gate.to_string(),
                to: h,
            }),
            _ => None,
        })
        .collect()
}
```

The only `return Vec::new()` is the deliberate height-0 case, which is the
documented behaviour (`a_chain_with_no_blocks_may_open_any_gate_at_zero`), not
mutation residue. No unconditional early return. No residue.

**Both anchored tests pass:**

```
$ cargo test -p sumchain-state --test runtime_activation -- a_first_start_refuses_before_it_records_what_it_refused
test a_first_start_refuses_before_it_records_what_it_refused ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 6 filtered out

$ cargo test -p sumchain-genesis --test activation_digest -- a_newly_introduced_gate_below_the_head_refuses_a_first_start
test a_newly_introduced_gate_below_the_head_refuses_a_first_start ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 16 filtered out
```

### What this audit cannot re-verify

The commit's "pre and post sha256 equal" claim was about the working tree at the
time of that commit. `crates/genesis/tests/activation_digest.rs` has since been
edited by this evidence pass (§1.3), so its hash today is deliberately not the
hash then. What is verifiable now, and is verified above, is the state that
matters: each anchor present exactly once, and no mutated form surviving in
either mutated file.

The commit is also candid about a gap, which is repeated here rather than left
in a commit message nobody re-reads: three of the six tests added by `6e64dd5`
assert the check returns **nothing** — the shipped default, a chain at height 0,
and a grandfathered gate below the head. A return-empty mutation cannot kill a
test that expects empty. **Those three are not covered by either mutation in this
run**, and no mutation exercising the "refuses chains it should not" direction
has been performed.
