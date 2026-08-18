#!/usr/bin/env bash
# RUNNER PATH-INDEPENDENCE recipe guards (no Docker/network/toolchain). Two parts:
#  (A) SOURCE-LEVEL controls are present and not weakened — the canonical recipe (one shared lib.sh
#      implementation: build at the canonical path /b0/tooling + two cargo/target remaps), the
#      transparent output-neutral wrapper, the exact-prefix leakage scan, the genuine
#      original-root-distinction refusal, the measure_fragment splice, and the RISC0 methods.rs
#      canonicalization in build.rs.
#  (B) FAST refusal negatives that run BEFORE any build: bad flags, non-64-hex toolchain identity,
#      non-40-hex build-git-sha, a non-executable wrapper, a symlinked source root, IDENTICAL
#      original checkout roots (distinguishes nothing), a missing/non-absolute canonical build path,
#      and an ambient RUSTFLAGS injection.
# The EMPIRICAL two-build byte-identity + real leakage proof runs on Linux (local gate) and in CI's
# real-backend RISC Zero canonical-path double-build; this test locks the controls + the refusals.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS="$(cd "$HERE/.." && pwd)"
BUILD_RS="$(cd "$SCRIPTS/../../b0-pre-measure-risc0" && pwd)/build.rs"
set +e
fails=0
ok()  { printf 'ok    %s\n' "$1"; }
bad() { printf 'FAIL  %s\n' "$1" >&2; fails=$((fails + 1)); }
has() { grep -qF -- "$2" "$1" && ok "$3" || bad "$3 [missing: $2]"; }
hasE(){ grep -qE -- "$2" "$1" && ok "$3" || bad "$3 [missing/re: $2]"; }

DBR="$SCRIPTS/double_build_runner.sh"
WRAP="$SCRIPTS/b0_rustc_remap_wrapper.sh"
LIB="$SCRIPTS/lib.sh"
MF="$SCRIPTS/measure_fragment.sh"
chmod +x "$WRAP" "$DBR" 2>/dev/null

echo "== (A) source-level controls =="
# ONE shared recipe implementation: double_build_runner sources lib.sh and uses its canonical helpers.
has "$DBR" '. "$HERE/lib.sh"'                         "double_build sources the shared lib.sh recipe helpers"
has "$DBR" 'b0_canonical_encoded_rustflags'          "double_build builds flags via the canonical helper (single source of truth)"
has "$DBR" 'RUSTC_WRAPPER="$WRAPPER_ABS"'             "double_build installs the transparent wrapper as RUSTC_WRAPPER"
has "$DBR" 'B0_RUSTC_EVIDENCE_DIR="$evid"'            "double_build records rustc invocation evidence outside the roots"
has "$DBR" 'produced no rustc invocation evidence'   "double_build fails closed if the wrapper produced no evidence"
has "$DBR" 'SAME original root'                       "double_build refuses identical original checkout roots (genuine distinction)"
has "$DBR" 'materialize'                              "double_build materializes each original root at the canonical build path"
has "$DBR" 'canonical build path coincides with a root' "double_build requires the canonical build path distinct from every root"
has "$DBR" 'identical CARGO_ENCODED_RUSTFLAGS'       "double_build refuses A/B presenting identical remap-from flags"
has "$DBR" 'b0_refuse_ambient_rustflags'             "double_build refuses ambient/inherited rustflags"
has "$DBR" 'b0_leakage_scan'                          "double_build runs the path-prefix/component leakage scan"
has "$DBR" 'uncontrolled path-prefix/component'       "double_build guarantee is path-prefix/component absence (not bare username/hostname)"
has "$DBR" 'REFUSED_ROOTS'                           "double_build scans the specific uncontrolled roots (not a generic /tmp reject)"
has "$LIB" 'b0_path_component_hit'                    "lib.sh matches username/hostname only as a full path component (not bare prose)"
has "$DBR" 'SOURCE_DATE_EPOCH=0'                      "double_build preserves SOURCE_DATE_EPOCH=0"
has "$DBR" 'BUILD_GIT_SHA="$EXPECT_SHA"'             "double_build exports the measured BUILD_GIT_SHA"
has "$DBR" 'NOT reproducible'                         "double_build requires the two builds byte-identical"
# Canonical, ENFORCED, RETAINED build argv (no opaque --build-cmd).
has "$DBR" 'ARGV+=(build --release --locked --features real-backend --manifest-path' "double_build constructs the canonical --release --locked --features real-backend argv"
has "$DBR" 'canonical argv missing required token'    "double_build asserts the argv carries the required flags (never an unproven claim)"
has "$DBR" 'B0_VENUE_EMBED="$EMBED"'                 "double_build binds the explicit B0_VENUE_EMBED state"
has "$DBR" 'RISC0 embedded guest image id differs'    "double_build requires (RISC0) the embedded guest byte-identical across A and B"
# GAP 1 (pin): the canonical build path is pinned to the exact literal /b0/tooling before any mutation.
has "$DBR" 'must be EXACTLY $CANON_REQUIRED'          "double_build pins --canonical-build-path to the literal /b0/tooling (GAP 1)"
has "$DBR" 'is a symlink (refused)'                   "double_build refuses a symlinked/aliased canonical path (GAP 1 filesystem)"
# GAP 2 (lock): a fixed exclusive non-blocking lock is held across the shared canonical path.
has "$DBR" 'flock -n 9'                               "double_build takes a non-blocking exclusive lock on the canonical path (GAP 2)"
has "$DBR" 'another run holds the canonical-path lock' "double_build refuses (no silent wait) if the lock is held (GAP 2)"
# GAP 3 (authenticated source inputs): full-build-input manifests, origin==origin and materialized==origin.
has "$DBR" 'b0_source_manifest_addr'                  "double_build authenticates build inputs via the source manifest (GAP 3)"
has "$DBR" 'DIFFERENT build-input manifests'          "double_build refuses A/B with different build-input manifests (GAP 3)"
has "$DBR" 'materialization not faithful'             "double_build refuses if a materialized tree != its origin manifest (GAP 3)"
has "$DBR" 'cp -Rp'                                   "double_build materializes mode-preserving (cp -Rp) so the manifest matches (GAP 3)"
# GAP 5 (cleanup): a cleanup failure FAILS the run, preserving diagnostics outside the canonical path.
has "$DBR" 'FAILED to remove canonical source'        "double_build fails the run if canonical cleanup fails (GAP 5)"
has "$DBR" 'trap - EXIT'                              "double_build preserves diagnostics (disarms the work-dir trap) on cleanup failure (GAP 5)"
# lib.sh canonical recipe: two remaps (cargo/target), unit-separator delimited, overlap/non-distinct refused.
has "$LIB" '%s%s--remap-path-prefix'                  "lib.sh CARGO_ENCODED_RUSTFLAGS delimits the two remaps with the unit separator"
has "$LIB" 'unit-separator-2-remap'                   "lib.sh structural recipe id names the two-remap encoded-flags format"
has "$LIB" 'build_at=%s'                              "lib.sh structural recipe id binds the canonical build path"
has "$LIB" 'B0_REMAP_TOOLING'                         "lib.sh names the canonical /b0/tooling build path"
has "$LIB" 'recipe roots overlap'                     "lib.sh refuses overlapping recipe roots"
has "$LIB" 'ratified-per-arch(authority-record)'      "lib.sh structural recipe id names the ratified-per-arch-toolchain RULE (not a digest)"
# lib.sh authenticated source manifest (GAP 3): fail-closed on non-regular/traversal; domain-separated addr.
has "$LIB" 'b0_source_manifest()'                     "lib.sh provides the full-build-input source manifest (GAP 3)"
has "$LIB" 'refused non-regular entry'                "lib.sh manifest refuses symlink/device/socket/fifo entries (GAP 3)"
has "$LIB" 'traversal component'                      "lib.sh manifest refuses a '..' traversal component (GAP 3)"
has "$LIB" 'b0-final-source-input-manifest/v1'        "lib.sh manifest address is domain-separated (GAP 3)"
# transparent wrapper: exactly two remaps for a compile, content-addressed record, exec "$@".
has "$WRAP" 'require exactly 2'                        "wrapper requires exactly two remaps on a compile"
has "$WRAP" 'source is NOT remapped'                  "wrapper documents the source is not remapped (canonical by construction)"
has "$WRAP" 'exec "$@"'                                "wrapper hands off to the real rustc unchanged"
has "$WRAP" 'B0_RUSTC_EVIDENCE_DIR'                   "wrapper refuses an unrecorded compile (evidence dir required)"
# measure_fragment splices the recipe facts into every provenance role (mandatory).
has "$MF" 'need_env B0_RUNNER_RECIPE_JSON'            "measure_fragment requires the runner-recipe facts"
has "$MF" 'entry["runner_recipe"] = recipe'          "measure_fragment splices runner_recipe into each provenance role"
# RISC0 methods.rs canonicalization (§G): env!(OUT_DIR) include form + fail-closed.
has "$BUILD_RS" 'canonicalize_methods_rs'             "risc0 build.rs canonicalizes methods.rs (§G)"
has "$BUILD_RS" 'concat!(env!(\"OUT_DIR\")'           "risc0 methods.rs _ELF include rewritten to the env!(OUT_DIR) form"
has "$BUILD_RS" 'refusing to emit a possibly path-dependent runner' "risc0 canonicalization is fail-closed if codegen changes"
# B0_VENUE_EMBED is a STRICT tri-state (1=real, 0/unset=stub, else refuse) — not "non-empty == real".
has "$BUILD_RS" 'fn decide_embed'                     "risc0 build.rs isolates the embed decision (decide_embed)"
has "$BUILD_RS" 'Some("1") => Ok(Embed::Real)'        "risc0 embed: only \"1\" selects the real embed"
has "$BUILD_RS" 'Some("0") | None => Ok(Embed::Stub)' "risc0 embed: \"0\" or unset selects the stub"
has "$BUILD_RS" 'invalid B0_VENUE_EMBED'              "risc0 embed refuses any other B0_VENUE_EMBED value (fail closed)"

echo "== (B) fast refusal negatives (no build reached) =="
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/srcA" "$WORK/srcB"
HEX40="$(printf '5%.0s' $(seq 40))"; HEX64="$(printf 'a%.0s' $(seq 64))"
# Common valid flags that get PAST parsing to reach a specific refusal; each negative overrides one.
n=0
base() { # <root-suffix> ; echoes the common valid flag set (distinct roots per call)
  n=$((n+1))
  printf '%s ' --candidate sp1 --manifest tools/runner/Cargo.toml --artifact release/runner --embed 0 \
    --src-a "$WORK/srcA" --src-b "$WORK/srcB" --root-a "$WORK/rA$n" --root-b "$WORK/rB$n" \
    --canonical-build-path /b0/tooling \
    --arch x86_64 --expect-build-git-sha "$HEX40" --wrapper "$WRAP" --per-arch-toolchain-identity "$HEX64"
}
run_dbr() { OUT="$("$DBR" "$@" 2>&1 1>/dev/null)"; RC=$?; }
refused() { # <desc> <substr>
  if [ "$RC" -ne 0 ] && printf '%s' "$OUT" | grep -qF -- "$2"; then ok "$1"; else
    bad "$1 [rc=$RC out=$(printf '%s' "$OUT" | tr '\n' '|' | head -c 200)]"; fi
}

# shellcheck disable=SC2046
run_dbr $(base)                                        # missing --recipe-out
refused "missing --recipe-out refused" "required flag is missing"
# shellcheck disable=SC2046
run_dbr $(base) --recipe-out "$WORK/r.json" --embed 2  # duplicate --embed (already in base)
refused "duplicate flag refused" "duplicate --embed"
# non-64-hex toolchain identity (override --per-arch-toolchain-identity by appending a duplicate? use a fresh set)
run_dbr --candidate sp1 --manifest tools/runner/Cargo.toml --artifact release/runner --embed 0 \
  --src-a "$WORK/srcA" --src-b "$WORK/srcB" --root-a "$WORK/rT1" --root-b "$WORK/rT2" --canonical-build-path /b0/tooling --arch x86_64 \
  --expect-build-git-sha "$HEX40" --wrapper "$WRAP" --per-arch-toolchain-identity nothex --recipe-out "$WORK/r.json"
refused "non-64-hex toolchain identity refused" "64 lowercase hex"
# non-40-hex build-git-sha
run_dbr --candidate sp1 --manifest tools/runner/Cargo.toml --artifact release/runner --embed 0 \
  --src-a "$WORK/srcA" --src-b "$WORK/srcB" --root-a "$WORK/rT3" --root-b "$WORK/rT4" --canonical-build-path /b0/tooling --arch x86_64 \
  --expect-build-git-sha deadbeef --wrapper "$WRAP" --per-arch-toolchain-identity "$HEX64" --recipe-out "$WORK/r.json"
refused "non-40-hex build-git-sha refused" "40 lowercase hex"
# bad --embed
run_dbr --candidate sp1 --manifest tools/runner/Cargo.toml --artifact release/runner --embed 9 \
  --src-a "$WORK/srcA" --src-b "$WORK/srcB" --root-a "$WORK/rT5" --root-b "$WORK/rT6" --canonical-build-path /b0/tooling --arch x86_64 \
  --expect-build-git-sha "$HEX40" --wrapper "$WRAP" --per-arch-toolchain-identity "$HEX64" --recipe-out "$WORK/r.json"
refused "bad --embed refused" "--embed must be 0|1"
# non-executable wrapper
touch "$WORK/notexec.sh"; chmod -x "$WORK/notexec.sh"
run_dbr --candidate sp1 --manifest tools/runner/Cargo.toml --artifact release/runner --embed 0 \
  --src-a "$WORK/srcA" --src-b "$WORK/srcB" --root-a "$WORK/rT7" --root-b "$WORK/rT8" --canonical-build-path /b0/tooling --arch x86_64 \
  --expect-build-git-sha "$HEX40" --wrapper "$WORK/notexec.sh" --per-arch-toolchain-identity "$HEX64" --recipe-out "$WORK/r.json"
refused "non-executable wrapper refused" "not executable"
# unknown/extra argument
# shellcheck disable=SC2046
run_dbr $(base) --recipe-out "$WORK/r.json" --bogus x
refused "unknown flag refused" "unknown/extra argument"
# IDENTICAL original checkout roots (distinguishes nothing)
run_dbr --candidate sp1 --manifest tools/runner/Cargo.toml --artifact release/runner --embed 0 \
  --src-a "$WORK/srcA" --src-b "$WORK/srcA" --root-a "$WORK/rT9" --root-b "$WORK/rT10" --canonical-build-path /b0/tooling --arch x86_64 \
  --expect-build-git-sha "$HEX40" --wrapper "$WRAP" --per-arch-toolchain-identity "$HEX64" --recipe-out "$WORK/r.json"
refused "identical original roots refused" "SAME original root"
# MISSING --canonical-build-path (now a required flag)
run_dbr --candidate sp1 --manifest tools/runner/Cargo.toml --artifact release/runner --embed 0 \
  --src-a "$WORK/srcA" --src-b "$WORK/srcB" --root-a "$WORK/rT15" --root-b "$WORK/rT16" --arch x86_64 \
  --expect-build-git-sha "$HEX40" --wrapper "$WRAP" --per-arch-toolchain-identity "$HEX64" --recipe-out "$WORK/r.json"
refused "missing --canonical-build-path refused" "required flag is missing"
# NON-LITERAL (relative) --canonical-build-path — refused by the literal pin before any filesystem work
run_dbr --candidate sp1 --manifest tools/runner/Cargo.toml --artifact release/runner --embed 0 \
  --src-a "$WORK/srcA" --src-b "$WORK/srcB" --root-a "$WORK/rT17" --root-b "$WORK/rT18" --canonical-build-path relative/path --arch x86_64 \
  --expect-build-git-sha "$HEX40" --wrapper "$WRAP" --per-arch-toolchain-identity "$HEX64" --recipe-out "$WORK/r.json"
refused "relative canonical build path refused (literal pin)" "must be EXACTLY /b0/tooling"
# WRONG ABSOLUTE --canonical-build-path (e.g. /b0/tooling/.. or another dir) — refused by the literal pin
run_dbr --candidate sp1 --manifest tools/runner/Cargo.toml --artifact release/runner --embed 0 \
  --src-a "$WORK/srcA" --src-b "$WORK/srcB" --root-a "$WORK/rT19" --root-b "$WORK/rT20" --canonical-build-path /b0/tooling/.. --arch x86_64 \
  --expect-build-git-sha "$HEX40" --wrapper "$WRAP" --per-arch-toolchain-identity "$HEX64" --recipe-out "$WORK/r.json"
refused "traversal canonical build path refused (literal pin)" "must be EXACTLY /b0/tooling"
# symlinked source root
ln -s "$WORK/srcA" "$WORK/srclink"
run_dbr --candidate sp1 --manifest tools/runner/Cargo.toml --artifact release/runner --embed 0 \
  --src-a "$WORK/srclink" --src-b "$WORK/srcB" --root-a "$WORK/rT11" --root-b "$WORK/rT12" --canonical-build-path /b0/tooling --arch x86_64 \
  --expect-build-git-sha "$HEX40" --wrapper "$WRAP" --per-arch-toolchain-identity "$HEX64" --recipe-out "$WORK/r.json"
refused "symlinked source root refused" "symlink"
# ambient RUSTFLAGS injection (reaches the recipe env assembly, refused before any build)
OUT="$(RUSTFLAGS='-C target-cpu=native' "$DBR" --candidate sp1 --manifest tools/runner/Cargo.toml \
  --artifact release/runner --embed 0 --src-a "$WORK/srcA" --src-b "$WORK/srcB" --root-a "$WORK/rT13" \
  --root-b "$WORK/rT14" --canonical-build-path /b0/tooling --arch x86_64 --expect-build-git-sha "$HEX40" --wrapper "$WRAP" \
  --per-arch-toolchain-identity "$HEX64" --recipe-out "$WORK/r.json" 2>&1 1>/dev/null)"; RC=$?
refused "ambient RUSTFLAGS refused" "ambient RUSTFLAGS"

echo "== (C) build.rs embed-selection execution test (0=stub, 1=real, else refuse) =="
if command -v rustc >/dev/null 2>&1; then
  BT="$WORK/build_rs_test"
  if rustc --edition 2021 --test "$BUILD_RS" -o "$BT" 2>"$WORK/bt.err"; then
    if "$BT" 2>/dev/null | grep -q 'test result: ok'; then
      ok "build.rs decide_embed execution test passes (strict tri-state)"
    else bad "build.rs decide_embed execution test did NOT pass"; fi
  else bad "build.rs decide_embed test did not compile: $(head -1 "$WORK/bt.err")"; fi
else
  echo "SKIP (C): rustc not on PATH"
fi

echo "== (D) authenticated materialization + stale + lock (GAP 3/4) =="
# Load the real lib.sh helpers used by the script (b0_source_manifest_addr, etc.).
# shellcheck source=../lib.sh
. "$LIB"
DW="$WORK/dsec"; mkdir -p "$DW"
mkorigin() { # <dir> : a small but representative build-input tree (regular files + a dir)
  mkdir -p "$1/src" "$1/.cargo"
  printf 'fn main(){}\n' > "$1/src/main.rs"
  printf '[package]\nname="x"\n' > "$1/Cargo.toml"
  printf 'net-offline\n' > "$1/.cargo/config.toml"
  chmod 0755 "$1/src"   # capture a non-644 mode so the manifest exercises mode
}
mkorigin "$DW/origA"; mkorigin "$DW/origB"
OA="$(b0_source_manifest_addr "$DW/origA")"; OB="$(b0_source_manifest_addr "$DW/origB")"
{ [ -n "$OA" ] && [ "$OA" = "$OB" ]; } && ok "identical origins produce equal manifest addresses (GAP 3)" \
  || bad "identical origins produced different/empty manifest addresses ($OA vs $OB)"
# Materialization (mode-preserving cp -Rp) reproduces the origin manifest exactly.
CAN="$DW/canon"; rm -rf "$CAN"; cp -Rp "$DW/origA" "$CAN"
MA="$(b0_source_manifest_addr "$CAN")"
[ "$MA" = "$OA" ] && ok "materialized (cp -Rp) manifest == origin manifest (GAP 3)" \
  || bad "materialized manifest $MA != origin $OA"
# STALE detection: an extra/mutated file at the canonical path changes the manifest (would be refused);
# the script's fresh `rm -rf` before cp removes it so the re-materialized manifest matches the origin.
echo 'STALE' > "$CAN/extra_stale_file"
MSTALE="$(b0_source_manifest_addr "$CAN")"
[ "$MSTALE" != "$OA" ] && ok "stale file at canonical path is DETECTED (manifest != origin -> refused) (GAP 4)" \
  || bad "stale file at canonical path was NOT detected"
rm -rf "$CAN"; cp -Rp "$DW/origA" "$CAN"   # the script's per-build fresh materialization
MCLEAN="$(b0_source_manifest_addr "$CAN")"
[ "$MCLEAN" = "$OA" ] && ok "fresh rm+cp REMOVES stale content and matches the origin manifest (GAP 4)" \
  || bad "fresh materialization did not match origin after a stale file"
# A symlink in the tree is refused (non-regular entry).
ln -sf "$CAN/Cargo.toml" "$CAN/evil_link"
if b0_source_manifest_addr "$CAN" >/dev/null 2>&1; then bad "symlink in the tree was NOT refused (GAP 3)"; else ok "symlink in a materialized tree is refused (GAP 3)"; fi
rm -f "$CAN/evil_link"
# Concurrent LOCK contention (GAP 4): needs flock; SKIP where unavailable (e.g. macOS dev).
if command -v flock >/dev/null 2>&1; then
  LK="$DW/lock"; ( exec 8>"$LK"; flock -n 8 || exit 3
    # While FD 8 holds the lock, a second non-blocking acquisition on the same file MUST fail.
    if flock -n -c 'true' "$LK"; then echo CONTEND_OK_NOTHELD; else echo CONTEND_REFUSED; fi
  ) > "$DW/lk.out" 2>/dev/null
  if grep -q CONTEND_REFUSED "$DW/lk.out"; then ok "concurrent lock contention is refused (second flock -n fails) (GAP 4)"; \
    else bad "concurrent lock contention was NOT refused: $(cat "$DW/lk.out")"; fi
else
  echo "SKIP (D-lock): flock not on PATH (CI/venue Linux has it)"
fi

echo "== (E) leakage scan: uncontrolled path-PREFIX / path-COMPONENT absence (not bare substrings) =="
# lib.sh is already sourced (part D). Refused set = HOME + a retained source root + the evidence root.
LREF="$(printf '%s\n' /home/runner /b0-input/a/tooling /tmp/b0-evid)"
lclean() { b0_leakage_scan "$1" "$LREF" runner myhost >/dev/null 2>&1; }        # exit 0 == clean
ltok()   { b0_leakage_scan "$1" "$LREF" runner myhost 2>/dev/null || true; }    # prints the hit token
# 1. Ordinary prose containing "runner" (the CI panic string) is ACCEPTED — the false positive we fixed.
if lclean "INELIGIBLE: RISC Zero measurement runner failed closed:"; then ok "prose 'measurement runner failed closed' accepted (not leakage)"; else bad "prose containing 'runner' was wrongly refused"; fi
# 2. /home/runner/... is REFUSED through the exact HOME prefix.
ltok "/home/runner/build/x" | grep -q 'path-prefix:/home/runner' && ok "/home/runner/... refused through HOME" || bad "/home/runner/... not refused via HOME"
# 3. /tmp/runner/... (no /tmp in the refused set here) is REFUSED via the /\$USER/ path component.
ltok "/tmp/runner/thing"    | grep -q 'user-path-component:/runner' && ok "/tmp/runner/... refused via the /\$USER/ path component" || bad "/\$USER/ component not refused"
# 4. Similar words are ACCEPTED (not a path component).
for w in prerunner runner_api; do
  if lclean "$w"; then ok "similar token '$w' accepted (not a path component)"; else bad "similar token '$w' wrongly refused"; fi
done
# 5. A real retained A/B source prefix + the evidence-root prefix remain REFUSED.
ltok "/b0-input/a/tooling/src/main.rs" | grep -q 'path-prefix:/b0-input/a/tooling' && ok "retained source prefix remains refused" || bad "retained source prefix not refused"
ltok "junk /tmp/b0-evid/rec.txt junk"  | grep -q 'path-prefix:/tmp/b0-evid' && ok "evidence-root prefix remains refused" || bad "evidence-root prefix not refused"

echo "----"
if [ "$fails" -eq 0 ]; then echo "RUNNER_PATH_INDEPENDENCE_PASS"; else echo "runner path-independence guards: $fails FAILURE(S)" >&2; fi
[ "$fails" -eq 0 ]
