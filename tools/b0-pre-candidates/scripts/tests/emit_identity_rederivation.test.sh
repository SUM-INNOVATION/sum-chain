#!/usr/bin/env bash
# CI test — the MEASUREMENT-BUILD IDENTITY RE-DERIVATION (measure_fragment.sh), PAST the preflight
# boundary. This is the test that would have caught the grid blocker: measure_fragment omitted
# --tooling-commit / --tooling-pathset-blake3 / --canonical-sp1-guest-artifact-address that the runner's
# `--emit-identity` REQUIRES, while derive_guest_set.sh passed them — a silent shell↔runner CLI drift.
#
# Four layers:
#   1. CONTRACT (audit-as-test): the ONE shared constructor b0_emit_identity_args emits a superset of the
#      runner's emit_identity `req(args, "--…")` set, per candidate, extracted mechanically from the
#      runner source. This makes the drift structurally impossible: if a future runner adds a required
#      --emit-identity arg, this fails until the shared constructor emits it (so BOTH callers get it).
#   2. STRUCTURAL: derive_guest_set.sh AND measure_fragment.sh both build their --emit-identity vector via
#      b0_emit_identity_args, and NEITHER hand-rolls a `--emit-identity` array literal (no way to drift).
#   3. FAIL-CLOSED: b0_emit_identity_args refuses SP1 without a guest-elf / canonical artifact address.
#   4. REACHES THE RE-DERIVATION (B0PRE_TESTONLY_REDERIVE + a contract stub runner): drive the ACTUAL
#      measure_fragment.sh past the preflight boundary to the _idargs re-derivation and assert (a) the
#      runner is invoked WITH the tooling pair + (SP1) the canonical artifact address, and (b) a WRONG
#      tooling_commit in the re-derived record is REFUSED by the exact-match compare — never proved.
# Terminal marker: EMIT_IDENTITY_REDERIVATION_TEST_PASS.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCR="$(cd "$HERE/.." && pwd)"          # .../b0-pre-candidates/scripts
CROOT="$(cd "$SCR/.." && pwd)"         # .../b0-pre-candidates
REPO="$(cd "$CROOT/../.." && pwd)"     # repo root
FIX="$HERE/fixtures/guest-set"
SP1MAIN="$REPO/tools/b0-pre-measure-sp1/src/main.rs"
RISC0MAIN="$REPO/tools/b0-pre-measure-risc0/src/main.rs"
SRC=507281e21e95a6a98e3480e25e12d1baab586e07
export PATH="$HOME/.cargo/bin:$PATH"; [ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env" 2>/dev/null
for c in b3sum python3 git; do command -v "$c" >/dev/null || { echo "SKIP: $c not available"; exit 0; }; done
PASS=0; FAIL=0
ok(){ echo "ok - $*"; PASS=$((PASS+1)); }
bad(){ echo "not ok - $*"; FAIL=$((FAIL+1)); }
. "$SCR/lib.sh"

# ---- the emit_identity req() set the runner ENFORCES, per candidate (mechanically extracted) ----------
runner_reqs() { # <main.rs> ; prints the sorted set of --flags emit_identity req()s
  awk '/fn emit_identity/{e=1} e&&/^    fn [a-z]/&&!/fn emit_identity/{e=0} e' "$1" \
    | grep -oE 'req\(args, "--[a-z0-9-]+"' | sed 's/req(args, "//;s/"//' | sort -u
}
# the flags b0_emit_identity_args actually emits, per candidate (dummy values)
builder_flags() { # <sp1|risc0>
  local gelf='' canon=''
  [ "$1" = sp1 ] && { gelf='/tmp/g.elf'; canon='CANON'; }
  b0_emit_identity_args "$1" x86_64 SPEC TREE LOCK RECIPE BDIG TCID SRCC true /tmp/vmat.json TCOMMIT TPATHSET "$gelf" "$canon" \
    | tr '\0' '\n' | grep -oE '^--[a-z0-9-]+' | sort -u
}
has_flag() { printf '%s\n' "$2" | grep -qxF -- "$1"; }  # <flag> <newline-list>

echo "### 1. CONTRACT: b0_emit_identity_args ⊇ runner emit_identity req() set (per candidate)"
for pair in "sp1 $SP1MAIN" "risc0 $RISC0MAIN"; do
  set -- $pair; cand="$1"; main="$2"
  reqs="$(runner_reqs "$main")"; emitted="$(builder_flags "$cand")"
  missing="$(comm -23 <(printf '%s\n' "$reqs") <(printf '%s\n' "$emitted"))"
  if [ -z "$missing" ]; then ok "$cand: shared constructor emits every runner-required emit_identity arg"
  else bad "$cand: shared constructor MISSING runner-required args: $(echo "$missing" | tr '\n' ' ')"; fi
  # the tooling pair must be there (the exact regression)
  { has_flag --tooling-commit "$emitted" && has_flag --tooling-pathset-blake3 "$emitted"; } \
    && ok "$cand: emits --tooling-commit + --tooling-pathset-blake3" || bad "$cand: missing a tooling arg"
done
# SP1-only reqs the constructor must add
sp1flags="$(builder_flags sp1)"
{ has_flag --canonical-sp1-guest-artifact-address "$sp1flags" && has_flag --guest-elf "$sp1flags"; } \
  && ok "sp1: emits --canonical-sp1-guest-artifact-address + --guest-elf" || bad "sp1: missing canonical-address/guest-elf"

echo "### 2. STRUCTURAL: both callers use the shared constructor; neither hand-rolls --emit-identity"
for s in derive_guest_set.sh measure_fragment.sh; do
  grep -q 'b0_emit_identity_args' "$SCR/$s" && ok "$s uses b0_emit_identity_args" || bad "$s does NOT use b0_emit_identity_args"
  # a hand-rolled vector would build an args array/list containing the bareword `--emit-identity` (the
  # shared constructor keeps that token ONLY inside lib.sh). Ignore comments AND die/echo message strings
  # (e.g. `die "runner --emit-identity $1 failed"`); any REMAINING occurrence is an independent construction.
  grep -vE '^[[:space:]]*#' "$SCR/$s" | grep -vE 'die "|echo "|note "' | grep -q -- '--emit-identity' \
    && bad "$s hand-rolls --emit-identity (drift risk)" || ok "$s has no hand-rolled --emit-identity (only comments/messages)"
done

echo "### 3. FAIL-CLOSED: b0_emit_identity_args refuses SP1 without guest-elf / canonical address"
b0_emit_identity_args sp1 x86_64 S T L R B TC SC true /tmp/v.json TCM TPS /tmp/g.elf '' >/dev/null 2>&1 && bad "sp1 without canonical-address accepted" || ok "sp1 without canonical-address refused"
b0_emit_identity_args sp1 x86_64 S T L R B TC SC true /tmp/v.json TCM TPS '' CANON >/dev/null 2>&1 && bad "sp1 without guest-elf accepted" || ok "sp1 without guest-elf refused"

# ---- 4. REACHES THE RE-DERIVATION (drive the ACTUAL measure_fragment past preflight) -----------------
command -v cargo >/dev/null || { echo "### 4. SKIP (no cargo): contract+structural layers already cover the drift"; echo "EMIT_IDENTITY_REDERIVATION_TEST: PASS=$PASS FAIL=$FAIL"; [ "$FAIL" = 0 ] && { echo EMIT_IDENTITY_REDERIVATION_TEST_PASS; exit 0; } || { echo EMIT_IDENTITY_REDERIVATION_TEST_FAIL; exit 1; }; }
case "$(uname -m)" in x86_64|amd64) HARCH=x86_64 ;; aarch64|arm64) HARCH=aarch64 ;; *) echo "### 4. SKIP unsupported host arch"; HARCH="" ;; esac
if [ -n "$HARCH" ]; then
WORK="$(mktemp -d)"
cleanup(){ for w in msrc tsrc; do git -C "$REPO" worktree remove --force "$WORK/$w" >/dev/null 2>&1 || true; done; rm -rf "$WORK"; }
trap cleanup EXIT
cargo build --release --manifest-path "$REPO/tools/b0-pre-validator/Cargo.toml" --bin measure-produce >/dev/null 2>&1 \
  || { echo "FATAL: build measure-produce failed"; exit 1; }
MP="$REPO/tools/b0-pre-validator/target/release/measure-produce"
git -C "$REPO" worktree add --quiet --detach "$WORK/msrc" "$SRC" || { echo "FATAL: worktree $SRC"; exit 1; }
git -C "$REPO" worktree add --quiet --detach "$WORK/tsrc" HEAD  || { echo "FATAL: worktree HEAD"; exit 1; }
MSRC="$WORK/msrc/tools/b0-pre-candidates"; TSRC="$WORK/tsrc"; TSCR="$TSRC/tools/b0-pre-candidates/scripts"
# TEST_ONLY guest set (3 fixture records + the committed real canonical ELF), same fixtures as the preflight smoke.
CANON="$WORK/canonical"; mkdir -p "$CANON"
cp "$FIX/canonical-sp1-guest-artifact.v1.json" "$CANON/canonical-sp1-guest-artifact.v1.json"
cp "$REPO/tools/b0-pre-validator/tests/fixtures/real_canonical_sp1_guest.elf" "$CANON/guest.elf"
RECS="$WORK/records"; mkdir -p "$RECS"; cp "$FIX/records/"*.json "$RECS/"
ALL="$WORK/all.json"; { printf '['; f1=1; for f in "$RECS"/sp1-x86_64.json "$RECS"/sp1-aarch64.json "$RECS"/risc0-x86_64.json; do [ "$f1" = 1 ] || printf ','; cat "$f"; f1=0; done; printf ']'; } > "$ALL"
SET="$WORK/set"; mkdir -p "$SET"
SPEC_HASH="$(python3 -c 'import json;print(json.load(open("'"$RECS"'/sp1-x86_64.json"))["b0_pre_spec_hash"])')"
SPEC_HASH="$SPEC_HASH" MEASURE_PRODUCE="$MP" CANONICAL_SP1_GUEST_PKG="$CANON" bash "$TSCR/derive_guest_set.sh" assemble "$RECS" "$SET" >/dev/null 2>&1 \
  || { echo "FATAL: assemble failed"; exit 1; }
STUBDIR="$WORK/stub"; mkdir -p "$STUBDIR"
# non-empty stub recipe + dep-seed: measure_fragment requires them to be non-empty files up front, but the
# REDERIVE path skips the recipe splice and exits before the dep-seed gate, so their CONTENT is unused here.
echo '{"testonly":"recipe"}'  > "$WORK/recipe.json"
echo '{"testonly":"depseed"}' > "$WORK/depseed.json"
# stub verifier-material harness: measure_fragment requires NON-EMPTY output (the stub runner echoes the
# fixture identity record, so the material CONTENT is unused in the re-derivation compare).
printf '#!/usr/bin/env bash\nprintf '"'"'{"testonly":"vmat"}'"'"'\n' > "$STUBDIR/vmat"; chmod +x "$STUBDIR/vmat"
# The contract stub runner: in --emit-identity mode it (a) RECORDS its argv, then (b) echoes the fixture
# phase-1 record for its candidate (so the exact-match compare passes) — OPTIONALLY mutating tooling_commit
# when STUB_MUTATE_TOOLING is set (to exercise the WRONG-tooling refusal). It also fails closed if any
# required tooling arg is absent (mirrors the real runner's req()), so an omission can never slip through.
make_stub() { # <cand>
  cat > "$STUBDIR/runner-$1" <<STUB
#!/usr/bin/env bash
printf '%s\n' "\$@" > "$WORK/argv-$1.txt"
have(){ printf '%s\n' "\$@" | grep -qx -- "\$1"; }
for need in --tooling-commit --tooling-pathset-blake3; do have "\$need" "\$@" || { echo "missing required \$need" >&2; exit 7; }; done
[ "$1" = sp1 ] && { have --canonical-sp1-guest-artifact-address "\$@" || { echo "missing required --canonical-sp1-guest-artifact-address" >&2; exit 7; }; }
rec="\$(python3 -c 'import json,sys; d=[r for r in json.load(open("$ALL")) if r["candidate"].lower()=="'$1'" and r["arch"]=="'$HARCH'"][0]; \
  import os; \
  d.__setitem__("tooling_commit","deadbeef"+d["tooling_commit"][8:]) if os.environ.get("STUB_MUTATE_TOOLING") else None; \
  print(json.dumps(d))')"
printf '%s' "\$rec"
STUB
  chmod +x "$STUBDIR/runner-$1"
}
prove_marker="$WORK/PROVING_LAUNCHED"
drive() { # <cand> ; env STUB_MUTATE_TOOLING optional. echoes rc; log at $WORK/out-<cand>/log
  local cand="$1" out="$WORK/out-$1"; rm -rf "$out"; mkdir -p "$out"; rm -f "$prove_marker" "$WORK/argv-$1.txt"
  make_stub "$cand"
  # values the injected re-derivation reads (must equal the fixture record so the compare passes)
  local rec="$RECS/$cand-$HARCH.json"
  local bdig tcid scommit
  bdig="$(python3 -c 'import json;print(json.load(open("'"$rec"'"))["builder_container_digest"])')"
  tcid="$(python3 -c 'import json;print(json.load(open("'"$rec"'"))["toolchain_identity"])')"
  scommit="$(python3 -c 'import json;print(json.load(open("'"$rec"'"))["source_commit"])')"
  local e=( B0PRE_TESTONLY_REDERIVE=1
    B0PRE_TESTONLY_BUILDER_DIGEST="$bdig" B0PRE_TESTONLY_TOOLCHAIN_IDENTITY="$tcid" B0PRE_TESTONLY_SOURCE_COMMIT="$scommit"
    B0_MEASURED_SOURCE_ROOT="$MSRC" B0_TOOLING_ROOT="$TSRC"
    SPEC_HASH="$SPEC_HASH" MEASURE_RUNNER="$STUBDIR/runner-$cand" MEASURE_PRODUCE="$MP"
    VMAT_BIN="$STUBDIR/vmat" PROV_BIN="/bin/true" PROVER_FIREWALL_SH="$TSCR/docker_firewall.sh"
    PROVER_REAL_DOCKER="/bin/true" PROVING_CGROUP=testonly.slice
    GUEST_SET_MANIFEST="$SET/coordination-manifest.json" IDENTITY_RECORDS="$ALL"
    OFFICIAL_JSON="$REPO/docs/b0-pre/fixtures/workload/official.json"
    B0_RUNNER_RECIPE_JSON="$WORK/recipe.json" B0_DEP_SEED_JSON="$WORK/depseed.json"
    B0_MEASUREMENT_AUTHORITY_PKG="$REPO/docs/b0-pre/fixtures/measurement-input-authority" REPO_DIR="$TSRC" )
  [ "$cand" = sp1 ] && e+=( VERIFIER_REF=sha256:0000000000000000000000000000000000000000000000000000000000000000 CANONICAL_SP1_GUEST_PKG="$CANON" )
  [ "$cand" = risc0 ] && e+=( PROVER_RISC0_HOME="$WORK/fake-r0home" CANONICAL_SP1_GUEST_PKG="$CANON" )
  [ -n "${STUB_MUTATE_TOOLING:-}" ] && e+=( STUB_MUTATE_TOOLING=1 )
  env "${e[@]}" bash "$TSCR/measure_fragment.sh" "$cand" "$HARCH" "$out" > "$out/log" 2>&1; echo $?
}

echo "### 4. REACHES RE-DERIVATION: drive measure_fragment past preflight to the _idargs re-derivation"
if [ "$HARCH" = x86_64 ]; then CANDS="sp1 risc0"; else CANDS=""; echo "### (aarch64 host: SP1/aarch64 identity-only, RISC0/aarch64 unsupported; re-derivation drive is x86-only)"; fi
for cand in $CANDS; do
  rc="$(drive "$cand")"; log="$WORK/out-$cand/log"; argv="$WORK/argv-$cand.txt"
  { [ "$rc" = 0 ] && grep -q "MEASURE_FRAGMENT_REDERIVE_OK" "$log"; } \
    && ok "$cand: reached the measurement-build re-derivation (past preflight) + compare PASSED" \
    || { bad "$cand: did not reach/pass the re-derivation (rc=$rc)"; tail -3 "$log"; }
  # the exact regression: the shell passed the tooling args (+ SP1 canonical address) to --emit-identity
  if [ -f "$argv" ]; then
    { grep -qxF -- '--tooling-commit' "$argv" && grep -qxF -- '--tooling-pathset-blake3' "$argv"; } \
      && ok "$cand: --emit-identity received --tooling-commit + --tooling-pathset-blake3" || bad "$cand: tooling arg NOT passed to --emit-identity"
    if [ "$cand" = sp1 ]; then grep -qxF -- '--canonical-sp1-guest-artifact-address' "$argv" && ok "sp1: --emit-identity received --canonical-sp1-guest-artifact-address" || bad "sp1: canonical address NOT passed"; fi
  else bad "$cand: runner argv not captured (re-derivation not reached)"; fi
  [ ! -s "$WORK/out-$cand/facts-$cand-$HARCH.json" ] && ok "$cand: no fragment emitted (exited before proving)" || bad "$cand: fragment emitted"
done

echo "### 4b. WRONG tooling_commit in the re-derived record is REFUSED by the exact-match compare"
for cand in $CANDS; do
  rc="$(STUB_MUTATE_TOOLING=1 drive "$cand")"; log="$WORK/out-$cand/log"
  { [ "$rc" != 0 ] && grep -qE "tooling_commit differs|identity != phase-1" "$log"; } \
    && ok "$cand: WRONG tooling_commit refused at re-derivation (before proving)" || { bad "$cand: wrong tooling_commit NOT refused (rc=$rc)"; tail -3 "$log"; }
done
fi

echo "EMIT_IDENTITY_REDERIVATION_TEST: PASS=$PASS FAIL=$FAIL"
[ "$FAIL" = 0 ] && { echo "EMIT_IDENTITY_REDERIVATION_TEST_PASS"; exit 0; } || { echo "EMIT_IDENTITY_REDERIVATION_TEST_FAIL"; exit 1; }
