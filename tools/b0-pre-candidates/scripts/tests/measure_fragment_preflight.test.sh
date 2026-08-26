#!/usr/bin/env bash
# CI SMOKE (TEST_ONLY; NO proving) — drives the ACTUAL measure_fragment.sh pre-proving path for BOTH SP1
# and RISC0 and proves the v8 `measure-produce --guest-set` canonical-package contract that the grid
# depends on:
#   * the three-argument call succeeds with a valid TEST_ONLY canonical package (SP1 and RISC0 cells);
#   * a missing canonical package refuses (before proving);
#   * a wrong/substituted OR mutated canonical package refuses (before proving);
#   * the derived guest-set matches the independently-assembled expected set;
#   * NO proving runner launches and NO fragment is emitted during any of these.
# It drives measure_fragment with B0PRE_TESTONLY_PREFLIGHT=1, which skips ONLY the MIA fail-fast gate
# (covered by dedicated verify-authority/sentinel tests) and EXITS before materialize/build/prove — so the
# guest-set / canonical-package gates run exactly as in production, with no prover involved. Fixtures are a
# self-consistent TEST_ONLY guest set (3 real identity records + the canonical artifact json; the ELF is the
# committed real_canonical_sp1_guest.elf, byte-identical). Terminal marker: MEASURE_FRAGMENT_PREFLIGHT_SMOKE_PASS.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCR="$(cd "$HERE/.." && pwd)"          # .../b0-pre-candidates/scripts
CROOT="$(cd "$SCR/.." && pwd)"         # .../b0-pre-candidates
REPO="$(cd "$CROOT/../.." && pwd)"     # repo root
FIX="$HERE/fixtures/guest-set"
SPEC=e933e7325c2639a48d8e25f20746d0f8abc822dee9fcfa87c2e6cdec226cf2a2
EXPECT_GS=4be497b79b4603eb11c6c45dcfd519b9e4d80de071b86c3cf76d5debb451b5f2
SRC=507281e21e95a6a98e3480e25e12d1baab586e07
WRONG_CANON_ADDR=8b063fdb061177f814ad33a21ac596b1b51b874ec871bb8d9de188721397312c
export PATH="$HOME/.cargo/bin:$PATH"; [ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env" 2>/dev/null
PASS=0; FAIL=0
ok(){ echo "ok - $*"; PASS=$((PASS+1)); }
bad(){ echo "not ok - $*"; FAIL=$((FAIL+1)); }
for c in b3sum sha256sum python3 git cargo; do command -v "$c" >/dev/null || { echo "SKIP: $c not available"; exit 0; }; done
# measure_fragment refuses a non-native arch (no emulation), so exercise the cells NATIVE to this host:
#   x86_64 host -> SP1/x86_64 (positive) + RISC0/x86_64 (positive); aarch64 host -> SP1/aarch64 (positive)
#   + RISC0/aarch64 (must REFUSE: native-ineligible). Either way we drive one SP1 and one RISC0 cell.
case "$(uname -m)" in x86_64|amd64) HARCH=x86_64 ;; aarch64|arm64) HARCH=aarch64 ;; *) echo "SKIP: unsupported host arch $(uname -m)"; exit 0 ;; esac

WORK="$(mktemp -d)"
cleanup(){ for w in msrc tsrc; do git -C "$REPO" worktree remove --force "$WORK/$w" >/dev/null 2>&1 || true; done; rm -rf "$WORK"; }
trap cleanup EXIT

echo "### build measure-produce"
cargo build --release --manifest-path "$REPO/tools/b0-pre-validator/Cargo.toml" --bin measure-produce >/dev/null 2>&1 \
  || { echo "FATAL: build measure-produce failed"; exit 1; }
MP="$REPO/tools/b0-pre-validator/target/release/measure-produce"

# CLEAN worktrees: measured @ RATIFIED_SOURCE_COMMIT (guest-core), tooling @ HEAD (carries THIS fix).
# Using a HEAD worktree for the tooling root isolates the two-root check from any working-tree dirtiness
# that earlier run.sh tests might leave, and makes measure_fragment resolve its scripts (produce_canonical_
# sp1_guest.sh etc.) from a clean committed tree.
echo "### clean worktrees: measured @ $SRC + tooling @ HEAD"
git -C "$REPO" worktree add --quiet --detach "$WORK/msrc" "$SRC"  || { echo "FATAL: worktree add $SRC failed"; exit 1; }
git -C "$REPO" worktree add --quiet --detach "$WORK/tsrc" HEAD    || { echo "FATAL: worktree add HEAD failed"; exit 1; }
MSRC="$WORK/msrc/tools/b0-pre-candidates"; TSRC="$WORK/tsrc"
SCR="$TSRC/tools/b0-pre-candidates/scripts"   # run the ACTUAL measure_fragment/derive_guest_set from the clean tooling tree
[ -d "$MSRC/guest-core" ] || { echo "FATAL: measured worktree lacks guest-core"; exit 1; }
# NB: invoke every script via `bash <script>` (measure_fragment.sh is committed non-exec) — never chmod a
# file inside the tooling worktree, which would dirty it and trip the two-root clean-tree check.

echo "### assemble the expected TEST_ONLY guest set (real 3-arg assembler)"
CANON="$WORK/canonical"; mkdir -p "$CANON"
cp "$FIX/canonical-sp1-guest-artifact.v1.json" "$CANON/canonical-sp1-guest-artifact.v1.json"
cp "$REPO/tools/b0-pre-validator/tests/fixtures/real_canonical_sp1_guest.elf" "$CANON/guest.elf"
RECS="$WORK/records"; mkdir -p "$RECS"; cp "$FIX/records/"*.json "$RECS/"
ALL="$WORK/all.json"; { printf '['; f1=1; for f in "$RECS"/sp1-x86_64.json "$RECS"/sp1-aarch64.json "$RECS"/risc0-x86_64.json; do [ "$f1" = 1 ] || printf ','; cat "$f"; f1=0; done; printf ']'; } > "$ALL"
SET="$WORK/set"; mkdir -p "$SET"
SPEC_HASH="$SPEC" MEASURE_PRODUCE="$MP" CANONICAL_SP1_GUEST_PKG="$CANON" \
  bash "$SCR/derive_guest_set.sh" assemble "$RECS" "$SET" >/dev/null 2>&1 || { echo "FATAL: assemble failed"; exit 1; }
GOT_GS="$(tr -d ' \t\n' < "$SET/r0_guest_set_hash.txt")"
[ "$GOT_GS" = "$EXPECT_GS" ] && ok "assembled expected guest-set ($EXPECT_GS)" || bad "assembled guest-set $GOT_GS != $EXPECT_GS"

# stubs: a proving runner / vmat / prov that mark if EVER executed (they must not be, in preflight); a
# no-op docker; non-empty recipe + dep-seed; the committed TEST_ONLY MIA package (members exist).
STUB="$WORK/stub"; mkdir -p "$STUB"; PROVE_MARKER="$WORK/PROVING_LAUNCHED"
printf '#!/usr/bin/env bash\necho LAUNCHED > "%s"\nexit 111\n' "$PROVE_MARKER" > "$STUB/runner"; chmod +x "$STUB/runner"
printf '#!/usr/bin/env bash\nexit 0\n' > "$STUB/docker"; chmod +x "$STUB/docker"
echo '{"testonly":"runner-recipe"}' > "$WORK/recipe.json"
echo '{"testonly":"dep-seed"}' > "$WORK/depseed.json"
MIA="$REPO/docs/b0-pre/fixtures/measurement-input-authority"

run_frag() { # <cand> <arch> <canon|-unset-> ; echoes rc; log at $WORK/out-<cand>-<arch>/log
  local cand="$1" arch="$2" canon="$3" out="$WORK/out-$1-$2"; rm -rf "$out"; mkdir -p "$out"; rm -f "$PROVE_MARKER"
  local e=( B0PRE_TESTONLY_PREFLIGHT=1
    B0_MEASURED_SOURCE_ROOT="$MSRC" B0_TOOLING_ROOT="$TSRC"
    SPEC_HASH="$SPEC" MEASURE_RUNNER="$STUB/runner" MEASURE_PRODUCE="$MP"
    VMAT_BIN="$STUB/runner" PROV_BIN="$STUB/runner" PROVER_FIREWALL_SH="$SCR/docker_firewall.sh"
    PROVER_REAL_DOCKER="$STUB/docker" PROVING_CGROUP=testonly.slice
    GUEST_SET_MANIFEST="$SET/coordination-manifest.json" IDENTITY_RECORDS="$ALL"
    OFFICIAL_JSON="$REPO/docs/b0-pre/fixtures/workload/official.json"
    B0_RUNNER_RECIPE_JSON="$WORK/recipe.json" B0_DEP_SEED_JSON="$WORK/depseed.json"
    B0_MEASUREMENT_AUTHORITY_PKG="$MIA" )
  [ "$cand" = sp1 ] && e+=( VERIFIER_REF=sha256:0000000000000000000000000000000000000000000000000000000000000000 )
  [ "$canon" != "-unset-" ] && e+=( CANONICAL_SP1_GUEST_PKG="$canon" )
  env "${e[@]}" bash "$SCR/measure_fragment.sh" "$cand" "$arch" "$out" > "$out/log" 2>&1; echo $?
}
no_prove() { [ ! -f "$PROVE_MARKER" ]; }

# Two-cell model: the two MEASUREMENT cells are SP1/x86_64 and RISC0/x86_64. measure_fragment refuses a
# NON-NATIVE arch (no cross-arch on a host), and SP1/aarch64 + RISC0/aarch64 are ratified-UNSUPPORTED.
# So the positive preflight + canonical-package negatives run ONLY on an x86_64 host; on an aarch64 host
# there is NO positive measurement cell — both aarch64 candidates are refused (verified below).
if [ "$HARCH" = x86_64 ]; then
  echo "### POSITIVE: SP1/x86_64 + RISC0/x86_64 preflight with the valid canonical package"
  for cand in sp1 risc0; do
    rc="$(run_frag "$cand" x86_64 "$CANON")"; log="$WORK/out-$cand-x86_64/log"
    { [ "$rc" = 0 ] && grep -q "MEASURE_FRAGMENT_PREFLIGHT_OK" "$log" && grep -q "r0_guest_set_hash=$EXPECT_GS" "$log"; } \
      && ok "$cand/x86_64: 3-arg preflight OK + derived guest-set matches expected" || { bad "$cand/x86_64: preflight failed (rc=$rc)"; sed -n '$p' "$log"; }
    no_prove && ok "$cand/x86_64: no proving runner launched" || bad "$cand/x86_64: proving runner LAUNCHED"
    [ ! -s "$WORK/out-$cand-x86_64/facts-$cand-x86_64.json" ] && ok "$cand/x86_64: no fragment emitted" || bad "$cand/x86_64: fragment emitted"
  done

  echo "### NEGATIVE (x86_64): missing canonical package refuses (before proving)"
  rc="$(run_frag sp1 x86_64 -unset-)"
  { [ "$rc" != 0 ] && grep -qiE "CANONICAL_SP1_GUEST_PKG|canonical SP1 guest package" "$WORK/out-sp1-x86_64/log"; } \
    && ok "missing canonical package refuses" || bad "missing canonical package NOT refused (rc=$rc)"
  no_prove && ok "missing-canonical: no proving runner launched" || bad "missing-canonical: proving LAUNCHED"

  echo "### NEGATIVE (x86_64): mutated canonical package refuses (independent verify recompute)"
  BADC="$WORK/canonical-mut"; cp -r "$CANON" "$BADC"
  python3 -c 'import json,sys;p=sys.argv[1];d=json.load(open(p));d["program_id"]="0"*64;open(p,"w").write(json.dumps(d))' "$BADC/canonical-sp1-guest-artifact.v1.json"
  rc="$(run_frag sp1 x86_64 "$BADC")"
  [ "$rc" != 0 ] && ok "mutated canonical package refuses" || bad "mutated canonical package NOT refused"
  no_prove && ok "mutated-canonical: no proving runner launched" || bad "mutated-canonical: proving LAUNCHED"

  echo "### NEGATIVE (x86_64): wrong/substituted canonical package (valid pkg, address != records reference) refuses"
  WRONGC="$WORK/canonical-wrong"; mkdir -p "$WRONGC"
  cp "$REPO/tools/b0-pre-validator/tests/fixtures/real_canonical_sp1_guest.json" "$WRONGC/canonical-sp1-guest-artifact.v1.json"
  cp "$REPO/tools/b0-pre-validator/tests/fixtures/real_canonical_sp1_guest.elf" "$WRONGC/guest.elf"
  rc="$(run_frag sp1 x86_64 "$WRONGC")"
  { [ "$rc" != 0 ] && grep -qiE "canonical artifact address not referenced|!= the supplied canonical" "$WORK/out-sp1-x86_64/log"; } \
    && ok "wrong/substituted canonical ($WRONG_CANON_ADDR) refuses" || bad "wrong/substituted canonical NOT refused (rc=$rc)"
  no_prove && ok "wrong-canonical: no proving runner launched" || bad "wrong-canonical: proving LAUNCHED"
else
  echo "### aarch64 host: BOTH cells ratified-UNSUPPORTED -> refused BEFORE proving (no measurement)"
  rc="$(run_frag sp1 aarch64 "$CANON")"; log="$WORK/out-sp1-aarch64/log"
  { [ "$rc" != 0 ] && grep -qiE "native-ineligible|ratified unsupported|sp1-aarch64-groth16-no-arm-backend" "$log"; } \
    && ok "sp1/aarch64: refused (ratified-unsupported; identity-only)" || bad "sp1/aarch64: NOT refused (rc=$rc)"
  no_prove && ok "sp1/aarch64: no proving runner launched" || bad "sp1/aarch64: proving runner LAUNCHED"
  rc="$(run_frag risc0 aarch64 "$CANON")"; log="$WORK/out-risc0-aarch64/log"
  { [ "$rc" != 0 ] && grep -qiE "native-ineligible|risc0-aarch64-x86-only" "$log"; } \
    && ok "risc0/aarch64: refused (native-ineligible)" || bad "risc0/aarch64: NOT refused (rc=$rc)"
  no_prove && ok "risc0/aarch64: no proving runner launched" || bad "risc0/aarch64: proving runner LAUNCHED"
fi

echo "### CLI CONTRACT: measure-produce --guest-set arg count"
rm -rf "$WORK/gs2" "$WORK/gs3"; mkdir -p "$WORK/gs2" "$WORK/gs3"
"$MP" --guest-set "$ALL" "$WORK/gs2" >/dev/null 2>&1 \
  && bad "2-arg --guest-set unexpectedly succeeded (contract regression)" || ok "2-arg --guest-set (missing canonical) refuses"
{ "$MP" --guest-set "$ALL" "$WORK/gs3" "$CANON" >/dev/null 2>&1 && [ "$(tr -d ' \t\n' < "$WORK/gs3/r0_guest_set_hash.txt")" = "$EXPECT_GS" ]; } \
  && ok "3-arg --guest-set succeeds + guest-set matches expected" || bad "3-arg --guest-set failed or mismatch"

echo "MEASURE_FRAGMENT_PREFLIGHT_SMOKE: PASS=$PASS FAIL=$FAIL"
[ "$FAIL" = 0 ] && { echo "MEASURE_FRAGMENT_PREFLIGHT_SMOKE_PASS"; exit 0; } || { echo "MEASURE_FRAGMENT_PREFLIGHT_SMOKE_FAIL"; exit 1; }
