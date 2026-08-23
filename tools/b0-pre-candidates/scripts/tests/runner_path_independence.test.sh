#!/usr/bin/env bash
# RUNNER PATH-INDEPENDENCE recipe guards (no Docker/network/toolchain). Parts:
#  (A) SOURCE-LEVEL controls are present and not weakened — the canonical recipe (one shared lib.sh
#      implementation: build at the canonical path /b0/tooling; the compiler-visible cargo home is the
#      LITERAL canonical /b0/cargo (materialized FRESH per build, removed fail-hard before + after, NOT
#      remapped); exactly ONE target remap (-> /b0/target)), the transparent output-neutral wrapper, the
#      exact-prefix leakage scan of BOTH runners AND the nested sp1 host binary, the fresh-per-build
#      dependency-seed materialization equality (origin == materialized-A == materialized-B), the genuine
#      original-root-distinction refusal, the measure_fragment splice, and the RISC0 methods.rs
#      canonicalization in build.rs.
#  (B) FAST refusal negatives that run BEFORE any build: bad flags, non-64-hex toolchain identity,
#      non-40-hex build-git-sha, a non-executable wrapper, a symlinked source root, IDENTICAL
#      original checkout roots (distinguishes nothing), a missing/non-absolute canonical build path,
#      and an ambient RUSTFLAGS injection.
#  (F) EXECUTABLE wrapper regression: a compile with exactly one target remap is accepted; a
#      --remap-path-prefix to /b0/cargo is refused (a deliberately per-build cargo home reproduces the
#      refusal); a zero-remap / altered-destination compile is refused; a nested sp1-native-bins compile
#      (no remaps) is accepted as path-independent-by-construction.
#  (G) EXECUTABLE seed regression: an authentic seed materializes and its address == the retained
#      authority; a missing / mutated / substituted seed is refused against that authority.
# The EMPIRICAL two-build byte-identity (runners A==B AND the nested sp1 binary A==B) + real leakage proof
# runs on Linux (local gate) and in CI's real-backend canonical-path double-build; this test locks the
# controls + the refusals.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS="$(cd "$HERE/.." && pwd)"
BUILD_RS="$(cd "$SCRIPTS/../../b0-pre-measure-risc0" && pwd)/build.rs"
EMBED_CANON="$(cd "$SCRIPTS/../../b0-pre-measure-risc0" && pwd)/src/embed_canon.rs"
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
has "$DBR" 'canonical path coincides with a root'    "double_build requires the canonical path distinct from every root"
has "$DBR" 'identical CARGO_ENCODED_RUSTFLAGS'       "double_build refuses A/B presenting identical remap-from flags"
# Canonical CARGO_HOME /b0/cargo: fresh per build, removed fail-hard before + after (canonical path != shared state).
has "$DBR" "CANON_CARGO='/b0/cargo'"                 "double_build pins the compiler-visible cargo home to the literal canonical /b0/cargo"
has "$DBR" 'CARGO_HOME="$CANON_CARGO"'               "double_build sets the build CARGO_HOME to the canonical /b0/cargo (never a per-build root)"
has "$DBR" 'cannot clean canonical cargo home before materialization' "double_build removes /b0/cargo FAIL-HARD before each build's fresh seed materialization"
has "$DBR" 'canonical cargo home $CANON_CARGO'       "double_build removes /b0/cargo FAIL-HARD after each build (no cache/state carried A->B)"
has "$DBR" 'MAT_CARGO'                               "double_build captures each build's materialized cargo-seed address (A==B==origin equality)"
has "$DBR" 'cargo_seed'                              "double_build binds the fresh-per-build seed origin==materialized-A==materialized-B equality into the recipe facts"
has "$DBR" 'b0_scan_nested_sp1_host_bins'            "double_build leakage-scans the NESTED sp1-native-bins host binary(ies) via the shared helper"
has "$DBR" 'nested_host_binaries'                    "double_build retains the nested host-binary evidence (relname/sha256/blake3/size/scan) in the recipe facts"
has "$LIB" 'b0_scan_nested_sp1_host_bins()'          "lib.sh provides the tested nested-host-binary scan helper"
has "$LIB" 'maxdepth 1 -type f ! -type l -perm -u+x' "lib.sh nested scan enumerates DIRECT-CHILD regular non-symlink executables"
has "$LIB" 'B0_EXPECTED_NESTED_SP1_HOST_BINS'        "lib.sh enforces the ratified expected nested host-binary basename set"
has "$LIB" 'materialized seed address'               "lib.sh seed materialization refuses a seed whose address != the retained authority"
has "$DBR" 'b0_refuse_ambient_rustflags'             "double_build refuses ambient/inherited rustflags"
has "$DBR" 'b0_leakage_scan'                          "double_build runs the path-prefix/component leakage scan"
has "$DBR" 'uncontrolled path-prefix/component'       "double_build guarantee is path-prefix/component absence (not bare username/hostname)"
has "$DBR" 'REFUSED_ROOTS'                           "double_build scans the specific uncontrolled roots (not a generic /tmp reject)"
has "$LIB" 'b0_path_component_hit'                    "lib.sh matches username/hostname only as a full path component (not bare prose)"
has "$DBR" 'SOURCE_DATE_EPOCH=0'                      "double_build preserves SOURCE_DATE_EPOCH=0"
has "$DBR" 'BUILD_GIT_SHA="$EXPECT_SHA"'             "double_build exports the measured BUILD_GIT_SHA"
has "$DBR" 'NOT reproducible'                         "double_build requires the two builds byte-identical"
# Canonical, ENFORCED, RETAINED build argv (no opaque --build-cmd).
has "$DBR" 'ARGV+=(build --release --locked --offline --features real-backend --manifest-path' "double_build constructs the canonical --release --locked --offline --features real-backend argv"
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
# GAP 5 (cleanup): a cleanup failure FAILS the run, preserving diagnostics outside the canonical paths.
has "$DBR" 'FAILED to remove $cleanup_fail'           "double_build fails the run if canonical cleanup fails (GAP 5)"
has "$DBR" 'cleanup_fail="canonical source'           "double_build fail-hard removes the canonical source after each build (GAP 5)"
has "$DBR" 'canonical cargo home $CANON_CARGO'        "double_build fail-hard removes the canonical cargo home after each build (GAP 5)"
has "$DBR" 'trap - EXIT'                              "double_build preserves diagnostics (disarms the work-dir trap) on cleanup failure (GAP 5)"
# lib.sh canonical recipe: ONE target remap (the canonical cargo home is NOT remapped), overlap/non-distinct refused.
has "$LIB" 'remap:target=%s'                          "lib.sh structural recipe id names the single target remap"
has "$LIB" 'unit-separator-1-remap'                   "lib.sh structural recipe id names the ONE-remap (target only) encoded-flags format"
has "$LIB" 'canonical-by-construction,fresh-per-build' "lib.sh structural recipe id binds /b0/cargo as the canonical cargo home (fresh per build, not remapped)"
has "$LIB" 'build_at=%s'                              "lib.sh structural recipe id binds the canonical build path"
has "$LIB" 'B0_REMAP_TOOLING'                         "lib.sh names the canonical /b0/tooling build path"
has "$LIB" 'coincides with a canonical destination'   "lib.sh refuses a target root that coincides with a canonical destination (/b0/cargo or /b0/tooling)"
has "$LIB" 'ratified-per-arch(authority-record)'      "lib.sh structural recipe id names the ratified-per-arch-toolchain RULE (not a digest)"
# lib.sh authenticated source manifest (GAP 3): fail-closed on non-regular/traversal; domain-separated addr.
has "$LIB" 'b0_source_manifest()'                     "lib.sh provides the full-build-input source manifest (GAP 3)"
has "$LIB" 'refused non-regular entry'                "lib.sh manifest refuses symlink/device/socket/fifo entries (GAP 3)"
has "$LIB" 'traversal component'                      "lib.sh manifest refuses a '..' traversal component (GAP 3)"
has "$LIB" 'b0-final-source-input-manifest/v1'        "lib.sh manifest address is domain-separated (GAP 3)"
# transparent wrapper: exactly ONE target remap for a compile, /b0/cargo remap refused, content-addressed, exec "$@".
has "$WRAP" 'require exactly 1'                        "wrapper requires exactly ONE remap (target only) on a compile"
has "$WRAP" 'the cargo home is the literal canonical' "wrapper REFUSES a --remap-path-prefix to /b0/cargo (cargo home is canonical, not remapped)"
has "$WRAP" 'NEITHER the source NOR the cargo-home is remapped' "wrapper documents neither the source nor the canonical cargo-home is remapped"
has "$WRAP" 'path-independent BY CONSTRUCTION'        "wrapper documents the nested sp1 build is path-independent by the canonical /b0/cargo home"
has "$WRAP" 'exec "$@"'                                "wrapper hands off to the real rustc unchanged"
has "$WRAP" 'B0_RUSTC_EVIDENCE_DIR'                   "wrapper refuses an unrecorded compile (evidence dir required)"
# measure_fragment splices the recipe facts into every provenance role (mandatory).
has "$MF" 'need_env B0_RUNNER_RECIPE_JSON'            "measure_fragment requires the runner-recipe facts"
has "$MF" 'entry["runner_recipe"] = recipe'          "measure_fragment splices runner_recipe into each provenance role"
# RISC0 methods.rs canonicalization (§G): the guest ELF (which risc0-build writes under
# <target>/riscv-guest, never OUT_DIR) is COPIED into OUT_DIR + verified, and the _ELF include is
# rewritten to the env!(OUT_DIR) form. The pure string/path logic lives in src/embed_canon.rs
# (shared with the crate so `cargo test` runs its unit tests); build.rs does the fs copy + hashing.
has "$BUILD_RS" 'canonicalize_methods_rs'             "risc0 build.rs canonicalizes methods.rs (§G)"
has "$BUILD_RS" 'copy guest ELF into OUT_DIR'         "risc0 build.rs copies the guest ELF into OUT_DIR (risc0-build leaves it under riscv-guest)"
has "$BUILD_RS" 'RISC0_BUILD_LOCKED'                  "risc0 build.rs forces the guest sub-build --locked (RISC0_BUILD_LOCKED=1)"
has "$BUILD_RS" 'remove_var("RUSTC_WRAPPER")'         "risc0 build.rs removes RUSTC_WRAPPER for the guest sub-build (path-independent by canonical HOME+source)"
has "$EMBED_CANON" 'concat!(env!(\"OUT_DIR\")'        "risc0 methods.rs _ELF include rewritten to the env!(OUT_DIR) form"
has "$EMBED_CANON" 'refusing to emit a possibly path-dependent runner' "risc0 canonicalization is fail-closed if codegen changes"
# B0_VENUE_EMBED is a STRICT tri-state (1=real, 0/unset=stub, else refuse) — not "non-empty == real".
has "$BUILD_RS" 'fn decide_embed'                     "risc0 build.rs isolates the embed decision (decide_embed)"
has "$BUILD_RS" 'Some("1") => Ok(Embed::Real)'        "risc0 embed: only \"1\" selects the real embed"
has "$BUILD_RS" 'Some("0") | None => Ok(Embed::Stub)' "risc0 embed: \"0\" or unset selects the stub"
has "$BUILD_RS" 'invalid B0_VENUE_EMBED'              "risc0 embed refuses any other B0_VENUE_EMBED value (fail closed)"

echo "== (B) fast refusal negatives (no build reached) =="
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/srcA" "$WORK/srcB"
HEX40="$(printf '5%.0s' $(seq 40))"; HEX64="$(printf 'a%.0s' $(seq 64))"
# The four offline-provisioning flags are PRESENCE-checked in the required-flag loop; the dep-seed /
# protoc STRUCTURE is validated LATER (after the cheap literal-pin + wrapper + source gates), so these
# non-existent placeholder paths let each spelled-out negative reach the SPECIFIC cheap refusal it
# exercises (the base()-using negatives refuse at parse time or before --toolchain, so they omit these).
DSF=(--toolchain 1.90.0 --dep-seed-dir "$WORK/ds" --dep-seed-json "$WORK/dsj" --host-toolchain-attestation "$WORK/htc")
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
run_dbr $(base)                                        # missing --recipe-out (checked before --toolchain)
refused "missing --recipe-out refused" "required flag is missing"
# shellcheck disable=SC2046
run_dbr $(base) --recipe-out "$WORK/r.json" --embed 2  # duplicate --embed (parse-time, before required loop)
refused "duplicate flag refused" "duplicate --embed"
# non-64-hex toolchain identity
run_dbr --candidate sp1 --manifest tools/runner/Cargo.toml --artifact release/runner --embed 0 \
  --src-a "$WORK/srcA" --src-b "$WORK/srcB" --root-a "$WORK/rT1" --root-b "$WORK/rT2" --canonical-build-path /b0/tooling --arch x86_64 \
  --expect-build-git-sha "$HEX40" --wrapper "$WRAP" --per-arch-toolchain-identity nothex --recipe-out "$WORK/r.json" "${DSF[@]}"
refused "non-64-hex toolchain identity refused" "64 lowercase hex"
# non-40-hex build-git-sha
run_dbr --candidate sp1 --manifest tools/runner/Cargo.toml --artifact release/runner --embed 0 \
  --src-a "$WORK/srcA" --src-b "$WORK/srcB" --root-a "$WORK/rT3" --root-b "$WORK/rT4" --canonical-build-path /b0/tooling --arch x86_64 \
  --expect-build-git-sha deadbeef --wrapper "$WRAP" --per-arch-toolchain-identity "$HEX64" --recipe-out "$WORK/r.json" "${DSF[@]}"
refused "non-40-hex build-git-sha refused" "40 lowercase hex"
# bad --embed
run_dbr --candidate sp1 --manifest tools/runner/Cargo.toml --artifact release/runner --embed 9 \
  --src-a "$WORK/srcA" --src-b "$WORK/srcB" --root-a "$WORK/rT5" --root-b "$WORK/rT6" --canonical-build-path /b0/tooling --arch x86_64 \
  --expect-build-git-sha "$HEX40" --wrapper "$WRAP" --per-arch-toolchain-identity "$HEX64" --recipe-out "$WORK/r.json" "${DSF[@]}"
refused "bad --embed refused" "--embed must be 0|1"
# non-executable wrapper
touch "$WORK/notexec.sh"; chmod -x "$WORK/notexec.sh"
run_dbr --candidate sp1 --manifest tools/runner/Cargo.toml --artifact release/runner --embed 0 \
  --src-a "$WORK/srcA" --src-b "$WORK/srcB" --root-a "$WORK/rT7" --root-b "$WORK/rT8" --canonical-build-path /b0/tooling --arch x86_64 \
  --expect-build-git-sha "$HEX40" --wrapper "$WORK/notexec.sh" --per-arch-toolchain-identity "$HEX64" --recipe-out "$WORK/r.json" "${DSF[@]}"
refused "non-executable wrapper refused" "not executable"
# unknown/extra argument
# shellcheck disable=SC2046
run_dbr $(base) --recipe-out "$WORK/r.json" --bogus x
refused "unknown flag refused" "unknown/extra argument"
# IDENTICAL original checkout roots (distinguishes nothing)
run_dbr --candidate sp1 --manifest tools/runner/Cargo.toml --artifact release/runner --embed 0 \
  --src-a "$WORK/srcA" --src-b "$WORK/srcA" --root-a "$WORK/rT9" --root-b "$WORK/rT10" --canonical-build-path /b0/tooling --arch x86_64 \
  --expect-build-git-sha "$HEX40" --wrapper "$WRAP" --per-arch-toolchain-identity "$HEX64" --recipe-out "$WORK/r.json" "${DSF[@]}"
refused "identical original roots refused" "SAME original root"
# MISSING --canonical-build-path (required, checked before --toolchain)
run_dbr --candidate sp1 --manifest tools/runner/Cargo.toml --artifact release/runner --embed 0 \
  --src-a "$WORK/srcA" --src-b "$WORK/srcB" --root-a "$WORK/rT15" --root-b "$WORK/rT16" --arch x86_64 \
  --expect-build-git-sha "$HEX40" --wrapper "$WRAP" --per-arch-toolchain-identity "$HEX64" --recipe-out "$WORK/r.json" "${DSF[@]}"
refused "missing --canonical-build-path refused" "required flag is missing"
# NON-LITERAL (relative) --canonical-build-path — refused by the literal pin before any filesystem work
run_dbr --candidate sp1 --manifest tools/runner/Cargo.toml --artifact release/runner --embed 0 \
  --src-a "$WORK/srcA" --src-b "$WORK/srcB" --root-a "$WORK/rT17" --root-b "$WORK/rT18" --canonical-build-path relative/path --arch x86_64 \
  --expect-build-git-sha "$HEX40" --wrapper "$WRAP" --per-arch-toolchain-identity "$HEX64" --recipe-out "$WORK/r.json" "${DSF[@]}"
refused "relative canonical build path refused (literal pin)" "must be EXACTLY /b0/tooling"
# WRONG ABSOLUTE --canonical-build-path (e.g. /b0/tooling/.. or another dir) — refused by the literal pin
run_dbr --candidate sp1 --manifest tools/runner/Cargo.toml --artifact release/runner --embed 0 \
  --src-a "$WORK/srcA" --src-b "$WORK/srcB" --root-a "$WORK/rT19" --root-b "$WORK/rT20" --canonical-build-path /b0/tooling/.. --arch x86_64 \
  --expect-build-git-sha "$HEX40" --wrapper "$WRAP" --per-arch-toolchain-identity "$HEX64" --recipe-out "$WORK/r.json" "${DSF[@]}"
refused "traversal canonical build path refused (literal pin)" "must be EXACTLY /b0/tooling"
# symlinked source root
ln -s "$WORK/srcA" "$WORK/srclink"
run_dbr --candidate sp1 --manifest tools/runner/Cargo.toml --artifact release/runner --embed 0 \
  --src-a "$WORK/srclink" --src-b "$WORK/srcB" --root-a "$WORK/rT11" --root-b "$WORK/rT12" --canonical-build-path /b0/tooling --arch x86_64 \
  --expect-build-git-sha "$HEX40" --wrapper "$WRAP" --per-arch-toolchain-identity "$HEX64" --recipe-out "$WORK/r.json" "${DSF[@]}"
refused "symlinked source root refused" "symlink"
# ambient RUSTFLAGS injection (refused LATE — after the dep-seed gate + ENC assembly). Give it a minimal
# VALID risc0 dependency-seed + host-toolchain attestation (risc0 needs no protoc) so it reaches that
# specific refusal instead of the earlier dep-seed-structure gate.
VDS="$WORK/vds"; mkdir -p "$VDS/host-seed"; : > "$VDS/host-config.toml"
printf '{"candidate":"risc0","seed_units":[{"role":"host-cargo-home","seed_address":"%s"}]}\n' "$HEX64" > "$WORK/vdsj.json"
: > "$WORK/vhtc.json"
VDSF=(--toolchain 1.90.0 --dep-seed-dir "$VDS" --dep-seed-json "$WORK/vdsj.json" --host-toolchain-attestation "$WORK/vhtc.json")
OUT="$(RUSTFLAGS='-C target-cpu=native' "$DBR" --candidate risc0 --manifest tools/runner/Cargo.toml \
  --artifact release/runner --embed 0 --src-a "$WORK/srcA" --src-b "$WORK/srcB" --root-a "$WORK/rT13" \
  --root-b "$WORK/rT14" --canonical-build-path /b0/tooling --arch x86_64 --expect-build-git-sha "$HEX40" --wrapper "$WRAP" \
  --per-arch-toolchain-identity "$HEX64" --recipe-out "$WORK/r.json" "${VDSF[@]}" 2>&1 1>/dev/null)"; RC=$?
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
set +e   # lib.sh sets `set -euo pipefail`; restore this test's non-errexit contract so a captured
         # non-zero (e.g. a wrapper wdie in part F, or a seed-refusal in part G) does not abort the run.
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

echo "== (F) wrapper 1-remap + canonical cargo-home enforcement (executable) =="
# Drive the transparent wrapper directly with a fake real-rustc (/bin/true) and synthetic argv; the
# wrapper's fail-closed argv checks run BEFORE the exec, so the exit code + message prove the enforcement
# WITHOUT a toolchain. A deliberately per-build cargo-home remap (-> /b0/cargo) MUST reproduce the refusal.
if command -v b3sum >/dev/null 2>&1; then
  WEVID="$WORK/wevid"; mkdir -p "$WEVID"
  FAKE_RUSTC="$WORK/fake_rustc.sh"; printf '#!/bin/sh\nexit 0\n' > "$FAKE_RUSTC"; chmod +x "$FAKE_RUSTC"
  wrap_run() { OUT="$(B0_RUSTC_EVIDENCE_DIR="$WEVID" "$WRAP" "$FAKE_RUSTC" "$@" 2>&1 1>/dev/null)"; RC=$?; }
  # 1. A compile with EXACTLY ONE target remap is ACCEPTED (execs the fake rustc; records evidence).
  rm -f "$WEVID"/*.rec 2>/dev/null
  wrap_run --emit=link a.rs --remap-path-prefix=/b0-build/a/target=/b0/target
  { [ "$RC" -eq 0 ] && ls "$WEVID"/*.rec >/dev/null 2>&1; } \
    && ok "wrapper ACCEPTS a compile with exactly one target remap (records evidence)" \
    || bad "wrapper rejected a valid one-target-remap compile [rc=$RC out=$OUT]"
  # 2. A --remap-path-prefix to /b0/cargo is REFUSED (a per-build cargo home reproduces the refusal).
  wrap_run --emit=link a.rs --remap-path-prefix=/b0-build/a/target=/b0/target --remap-path-prefix=/b0-build/a/cargo=/b0/cargo
  { [ "$RC" -ne 0 ] && printf '%s' "$OUT" | grep -qF 'the cargo home is the literal canonical'; } \
    && ok "wrapper REFUSES a --remap-path-prefix to /b0/cargo (per-build cargo home reproduces the refusal)" \
    || bad "wrapper did not refuse a /b0/cargo remap [rc=$RC out=$OUT]"
  # 3. A non-nested compile with ZERO remaps is REFUSED (require exactly 1).
  wrap_run --emit=link a.rs
  { [ "$RC" -ne 0 ] && printf '%s' "$OUT" | grep -qF 'require exactly 1'; } \
    && ok "wrapper REFUSES a non-nested compile with zero remaps (require exactly 1)" \
    || bad "wrapper did not refuse a zero-remap compile [rc=$RC out=$OUT]"
  # 4. A SECOND remap to an arbitrary destination is REFUSED (altered/extra destination).
  wrap_run --emit=link a.rs --remap-path-prefix=/b0-build/a/target=/b0/target --remap-path-prefix=/x=/somewhere
  { [ "$RC" -ne 0 ] && printf '%s' "$OUT" | grep -qF 'altered/extra --remap-path-prefix destination'; } \
    && ok "wrapper REFUSES an altered/extra remap destination" \
    || bad "wrapper did not refuse an extra remap destination [rc=$RC out=$OUT]"
  # 5. The NESTED sp1-native-bins compile (no remaps) is ACCEPTED (path-independent by canonical /b0/cargo).
  rm -f "$WEVID"/*.rec 2>/dev/null
  wrap_run --emit=link a.rs --out-dir /b0/target/release/build/sp1-native-bins/x
  { [ "$RC" -eq 0 ] && grep -lq 'kind=nested' "$WEVID"/*.rec 2>/dev/null; } \
    && ok "wrapper ACCEPTS the nested sp1-native-bins compile (kind=nested; canonical /b0/cargo, not remap-enforced)" \
    || bad "wrapper mishandled the nested sp1-native-bins compile [rc=$RC out=$OUT]"
else
  echo "SKIP (F): b3sum not on PATH (CI/venue Linux has it)"
fi

echo "== (G) fresh-per-build seed materialization: authentic accepted, missing/mutated/substituted refused =="
# lib.sh is already sourced (part D). b0_materialize_seed materializes an INDEPENDENT copy of the
# authenticated seed into a cargo home and REFUSES (dies) unless its inventory address == the retained
# authority — the exact fail-hard the double-build runs per build A and B against the canonical /b0/cargo.
SEEDDIR="$WORK/seed/host-seed"; mkdir -p "$SEEDDIR/vendorpkg"
printf 'crate-bytes-v1\n' > "$SEEDDIR/vendorpkg/lib.rs"
: > "$WORK/seed/host-config.toml"
SEED_ADDR="$(b0_seed_inventory_address "$SEEDDIR")"
CHOME="$WORK/chome"
# 1. Authentic seed materializes and returns an address == the retained authority.
GOT="$(b0_materialize_seed "$SEEDDIR" "$WORK/seed/host-config.toml" "$CHOME" "$SEED_ADDR" 2>/dev/null)"
{ [ -n "$SEED_ADDR" ] && [ "$GOT" = "$SEED_ADDR" ]; } \
  && ok "authentic seed materializes and address == retained authority" \
  || bad "authentic seed materialization failed (got '$GOT' vs '$SEED_ADDR')"
# 2. A MUTATED seed (different bytes) yields a different address -> REFUSED vs the retained authority.
printf 'crate-bytes-TAMPERED\n' > "$SEEDDIR/vendorpkg/lib.rs"
if b0_materialize_seed "$SEEDDIR" "$WORK/seed/host-config.toml" "$CHOME" "$SEED_ADDR" >/dev/null 2>&1; then
  bad "mutated seed was NOT refused against the retained authority"
else ok "mutated seed materialization is REFUSED (address != retained authority)"; fi
# 3. A MISSING seed dir is refused.
if b0_materialize_seed "$WORK/seed/nonexistent" "$WORK/seed/host-config.toml" "$CHOME" "$SEED_ADDR" >/dev/null 2>&1; then
  bad "missing seed dir was NOT refused"
else ok "missing seed dir is REFUSED (seed absent)"; fi
# 4. A SUBSTITUTED seed (valid tree, wrong content) is refused against the original authority.
SUB="$WORK/seed2/host-seed"; mkdir -p "$SUB/otherpkg"; printf 'substitute\n' > "$SUB/otherpkg/x.rs"
if b0_materialize_seed "$SUB" "$WORK/seed/host-config.toml" "$CHOME" "$SEED_ADDR" >/dev/null 2>&1; then
  bad "substituted seed was NOT refused"
else ok "substituted seed materialization is REFUSED (address != retained authority)"; fi

echo "== (H) nested SP1 host-binary scan b0_scan_nested_sp1_host_bins (SIGPIPE-safe, full-consumption) =="
# lib.sh is already sourced (part D). Each case runs the helper UNDER `set -euo pipefail` in a subshell to
# prove it can never SIGPIPE (rc 141) on a multi-thousand-file nested target dir. REF = a synthetic refused set.
NROOT="$WORK/nested"; EXP="sp1-core-executor-runner-binary"
REF="$(printf '%s\n' /b0-input/a /b0-input/b /b0-build/a/target /tmp/b0-evid)"
mk_release() { # <release_dir> : realistic nested layout — MANY non-exec direct children + excluded subdirs
  local rd="$1" i
  mkdir -p "$rd/deps" "$rd/.fingerprint/x" "$rd/build/y" "$rd/incremental/z"
  : > "$rd/.cargo-lock"; : > "$rd/.rustc_info.json"
  for i in $(seq 1 2500); do : > "$rd/lib_dep_$i.rlib"; done       # 2500+ non-exec direct children
  : > "$rd/deps/inner.rlib"; : > "$rd/.fingerprint/x/dep"; : > "$rd/build/y/out"; : > "$rd/incremental/z/mod"
}
# 1. thousands of files + one qualifying executable -> PASSES, no rc141, under set -euo pipefail.
RD="$NROOT/t1/release"; mk_release "$RD"; printf '#!/bin/sh\ntrue\n' > "$RD/$EXP"; chmod +x "$RD/$EXP"
( set -euo pipefail; b0_scan_nested_sp1_host_bins "$RD" "$REF" runner myhost "$NROOT/t1" ) >"$WORK/h1.out" 2>"$WORK/h1.err"; rc=$?
{ [ "$rc" = 0 ] && grep -q "release/$EXP" "$WORK/h1.out"; } \
  && ok "thousands of files + qualifying exec -> pass, no rc141 (rc=$rc)" \
  || bad "nested scan failed on large dir [rc=$rc err=$(head -c160 "$WORK/h1.err")]"
# 2. the executable need NOT sort first (many 'lib_dep_*'/'.cargo-lock' sort before 'sp1-core-...') -> still found.
grep -q "release/$EXP" "$WORK/h1.out" && ok "qualifying exec found although it does NOT sort first" || bad "exec not found when not sorting first"
# 3. zero executables -> REFUSED.
RD="$NROOT/t3/release"; mk_release "$RD"
( set -euo pipefail; b0_scan_nested_sp1_host_bins "$RD" "$REF" runner myhost "$NROOT/t3" ) 2>"$WORK/h3.err"; rc=$?
{ [ "$rc" != 0 ] && grep -qi "no qualifying" "$WORK/h3.err"; } && ok "zero executables refused" || bad "zero-exec not refused [rc=$rc]"
# 4. a leaked A/B path in ONE of MULTIPLE executables -> REFUSED (per-exec leakage; override expected set).
RD="$NROOT/t4/release"; mk_release "$RD"
printf '#!/bin/sh\ntrue\n' > "$RD/binA"; chmod +x "$RD/binA"
printf '#!/bin/sh\n# embeds /b0-input/b/tooling/leaked\ntrue\n' > "$RD/binB"; chmod +x "$RD/binB"
( set -euo pipefail; B0_EXPECTED_NESTED_SP1_HOST_BINS="binA binB" b0_scan_nested_sp1_host_bins "$RD" "$REF" runner myhost "$NROOT/t4" ) 2>"$WORK/h4.err"; rc=$?
{ [ "$rc" != 0 ] && grep -qi "leakage" "$WORK/h4.err"; } && ok "leaked A/B path in one of multiple executables refused" || bad "multi-exec leak not refused [rc=$rc err=$(head -c160 "$WORK/h4.err")]"
# 5. symlink substitution -> REFUSED (find ! -type l excludes it -> empty qualifying set).
RD="$NROOT/t5/release"; mk_release "$RD"; ln -s /bin/sh "$RD/$EXP"
( set -euo pipefail; b0_scan_nested_sp1_host_bins "$RD" "$REF" runner myhost "$NROOT/t5" ) 2>"$WORK/h5.err"; rc=$?
[ "$rc" != 0 ] && ok "symlink substitution refused (not a qualifying regular executable)" || bad "symlink substitution not refused [rc=$rc]"
# 6. clean real-shaped layout -> PASSES under set -euo pipefail with retained sha256 evidence.
RD="$NROOT/t6/release"; mk_release "$RD"; printf '#!/bin/sh\ntrue\n' > "$RD/$EXP"; chmod +x "$RD/$EXP"
( set -euo pipefail; b0_scan_nested_sp1_host_bins "$RD" "$REF" runner myhost "$NROOT/t6" ) >"$WORK/h6.out" 2>"$WORK/h6.err"; rc=$?
{ [ "$rc" = 0 ] && [ "$(awk -F'\t' 'NR==1{print length($2)}' "$WORK/h6.out")" = 64 ] && awk -F'\t' 'NR==1{exit !($5=="clean")}' "$WORK/h6.out"; } \
  && ok "clean real-shaped layout passes under set -euo pipefail with retained sha256/size/scan evidence" \
  || bad "clean layout failed [rc=$rc out=$(head -c160 "$WORK/h6.out") err=$(head -c160 "$WORK/h6.err")]"

echo "----"
if [ "$fails" -eq 0 ]; then echo "RUNNER_PATH_INDEPENDENCE_PASS"; else echo "runner path-independence guards: $fails FAILURE(S)" >&2; fi
[ "$fails" -eq 0 ]
