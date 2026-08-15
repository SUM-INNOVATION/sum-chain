#!/usr/bin/env bash
# DOUBLE clean build + reproducibility gate for the SP1/RISC0 runner (or the guest): build the
# artifact TWICE from clean, in two SEPARATE build roots, and require the two outputs BYTE-IDENTICAL.
# This is the reproducibility check (two genuinely distinct builds, never one replayed) plus a
# leakage scan that fails closed if the artifact embeds any build-environment-specific bytes
# (build-root paths, hostname/username, or a wall-clock timestamp). Self-contained like the other
# provision_*/run_* scripts (own die + own hash helpers; sources NO lib.sh).
#
# The build itself is supplied as ONE opaque command string (--build-cmd) that performs a single
# CLEAN build and prints the ABSOLUTE path of the produced artifact on its LAST stdout line. This
# script never assumes a toolchain: it runs that command in root-a, then (fully separately, wall-
# clock-ordered) in root-b, each with BUILD_GIT_SHA exported to the ratified source commit, preserves
# each produced artifact's bytes, and compares them. In strict order:
#   1. parse EXPLICIT flags (unknown / extra / missing / duplicate flags all die);
#   2. require root-a and root-b DISTINCT, non-symlink, empty-or-creatable, and neither nested in the
#      other;
#   3. build in root-a (capture start_a/end_a), then in root-b (capture start_b/end_b) with
#      BUILD_GIT_SHA exported; require end_b > end_a (proves two wall-clock-separated builds);
#   4. require the two preserved artifacts byte-identical (cmp) AND matching sha256 AND blake3 — any
#      difference dies "runner is NOT reproducible: build A != build B" after printing both digests;
#   5. leakage scan (strings + grep): die if the artifact embeds root-a, root-b, $HOME, $USER, the
#      hostname, or an RFC3339/date-like timestamp;
#   6. emit a machine-readable KEY=VALUE attestation block to STDOUT; diagnostics go to STDERR.
#
# Usage:
#   double_build_runner.sh --build-cmd <cmd string> --root-a <dir> --root-b <dir> \
#       --arch <x86_64|aarch64> --expect-build-git-sha <40-hex>
set -euo pipefail

die() { printf 'DOUBLE-BUILD-REFUSED: %s\n' "$*" >&2; exit 7; }
log() { printf '%s\n' "$*" >&2; }
require_cmd() { command -v "$1" >/dev/null 2>&1 || die "required command '$1' not found on PATH"; }

# Bare 64-hex sha256 of a file (coreutils sha256sum or macOS shasum). Self-contained (no lib.sh).
sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
  else die "no sha256 tool (sha256sum / shasum) available"; fi
}
# Bare 64-hex blake3 of a file (b3sum is a venue dependency).
blake3_file() {
  command -v b3sum >/dev/null 2>&1 || die "no blake3 tool (b3sum) available"
  b3sum "$1" | awk '{print $1}'
}

# --- (1) explicit flag parsing (no positional / env args; unknown / extra / missing / dup => die) -
BUILD_CMD=""; ROOT_A=""; ROOT_B=""; ARCH=""; EXPECT_SHA=""
seen_cmd=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --build-cmd) [ "$#" -ge 2 ] || die "--build-cmd requires a value"
                 [ "$seen_cmd" -eq 0 ] || die "duplicate --build-cmd (ambiguous)"
                 BUILD_CMD="$2"; seen_cmd=1; shift 2 ;;
    --root-a)    [ "$#" -ge 2 ] || die "--root-a requires a value"
                 [ -z "$ROOT_A" ] || die "duplicate --root-a (ambiguous)"
                 ROOT_A="$2"; shift 2 ;;
    --root-b)    [ "$#" -ge 2 ] || die "--root-b requires a value"
                 [ -z "$ROOT_B" ] || die "duplicate --root-b (ambiguous)"
                 ROOT_B="$2"; shift 2 ;;
    --arch)      [ "$#" -ge 2 ] || die "--arch requires a value"
                 [ -z "$ARCH" ] || die "duplicate --arch (ambiguous)"
                 ARCH="$2"; shift 2 ;;
    --expect-build-git-sha) [ "$#" -ge 2 ] || die "--expect-build-git-sha requires a value"
                 [ -z "$EXPECT_SHA" ] || die "duplicate --expect-build-git-sha (ambiguous)"
                 EXPECT_SHA="$2"; shift 2 ;;
    *) die "unknown/extra argument (only --build-cmd/--root-a/--root-b/--arch/--expect-build-git-sha accepted; no positional/env args): $1" ;;
  esac
done
[ "$seen_cmd" -eq 1 ] || die "--build-cmd is required"
[ -n "$BUILD_CMD" ] || die "--build-cmd must be a non-empty command string"
[ -n "$ROOT_A" ] || die "--root-a is required"
[ -n "$ROOT_B" ] || die "--root-b is required"
[ -n "$ARCH" ] || die "--arch is required"
[ -n "$EXPECT_SHA" ] || die "--expect-build-git-sha is required"
case "$ARCH" in x86_64|aarch64) ;; *) die "--arch must be x86_64|aarch64 (got '$ARCH')" ;; esac
printf '%s' "$EXPECT_SHA" | grep -Eq '^[0-9a-f]{40}$' \
  || die "--expect-build-git-sha must be exactly 40 lowercase hex (the ratified source commit): '$EXPECT_SHA'"

require_cmd cmp
require_cmd strings
require_cmd b3sum
require_cmd date

# --- (2) root-a / root-b: distinct, non-symlink, empty-or-creatable, non-nested ------------------
# Refuse a symlink BEFORE creating anything (a symlinked root could redirect writes out of the root).
for r in "$ROOT_A" "$ROOT_B"; do
  [ ! -L "$r" ] || die "build root is a symlink (refused): $r"
done
prepare_root() {
  local r="$1" name="$2"
  if [ -e "$r" ]; then
    [ ! -L "$r" ] || die "$name is a symlink (refused): $r"
    [ -d "$r" ] || die "$name exists and is not a directory: $r"
    [ -z "$(ls -A "$r" 2>/dev/null)" ] || die "$name must be EMPTY (single-use clean build root): $r"
  else
    mkdir -p "$r" || die "cannot create $name: $r"
  fi
}
prepare_root "$ROOT_A" "--root-a"
prepare_root "$ROOT_B" "--root-b"
A_ABS="$(cd "$ROOT_A" && pwd)" || die "cannot resolve --root-a: $ROOT_A"
B_ABS="$(cd "$ROOT_B" && pwd)" || die "cannot resolve --root-b: $ROOT_B"
[ "$A_ABS" != "$B_ABS" ] || die "--root-a and --root-b must be DISTINCT (both resolve to $A_ABS)"
case "$B_ABS/" in "$A_ABS"/*) die "--root-b is nested under --root-a (refused): $B_ABS under $A_ABS" ;; esac
case "$A_ABS/" in "$B_ABS"/*) die "--root-a is nested under --root-b (refused): $A_ABS under $B_ABS" ;; esac

work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT

# --- (3) two clean, wall-clock-separated builds; BUILD_GIT_SHA exported to the ratified commit ----
# Run the opaque build command with cwd == the build root and BUILD_GIT_SHA in its environment. The
# artifact path is the LAST stdout line. Preserve each artifact's bytes IMMEDIATELY (so build B can
# never overwrite build A's output and be silently compared to itself — "no single build for two").
run_one() {
  local root="$1" name="$2" preserve="$3" out last
  if ! out="$(cd "$root" && BUILD_GIT_SHA="$EXPECT_SHA" bash -c "$BUILD_CMD")"; then
    die "clean build $name FAILED in $root"
  fi
  last="$(printf '%s\n' "$out" | tail -n1)"
  [ -n "$last" ] || die "build $name produced no artifact path on its last stdout line"
  case "$last" in /*) ;; *) die "build $name artifact path is not absolute: '$last'" ;; esac
  [ -f "$last" ] || die "build $name artifact path does not name a regular file: '$last'"
  cp -f "$last" "$preserve" || die "cannot preserve build $name artifact ($last)"
  printf '%s' "$last"
}

start_a="$(date +%s)"
art_a="$(run_one "$A_ABS" "A" "$work/artifact.a")"
end_a="$(date +%s)"
log "build A done: artifact=$art_a (start=$start_a end=$end_a)"

start_b="$(date +%s)"
art_b="$(run_one "$B_ABS" "B" "$work/artifact.b")"
end_b="$(date +%s)"
log "build B done: artifact=$art_b (start=$start_b end=$end_b)"

# Wall-clock separation: build B must have started only after build A finished, and finished strictly
# later — a proof the two builds were genuinely separate runs, not one build counted twice.
[ "$start_b" -ge "$end_a" ] || die "build B started ($start_b) before build A finished ($end_a); refusing"
[ "$end_b" -gt "$end_a" ] \
  || die "builds were not wall-clock separated (end_b=$end_b not > end_a=$end_a); refusing to accept a possibly-single build as two"

# --- (4) require byte-identical artifacts (cmp) + matching sha256 AND blake3 ----------------------
sha_a="$(sha256_file "$work/artifact.a")"; sha_b="$(sha256_file "$work/artifact.b")"
b3_a="$(blake3_file "$work/artifact.a")";  b3_b="$(blake3_file "$work/artifact.b")"
if ! cmp -s "$work/artifact.a" "$work/artifact.b"; then
  log "build A: sha256=$sha_a blake3=$b3_a"
  log "build B: sha256=$sha_b blake3=$b3_b"
  die "runner is NOT reproducible: build A != build B"
fi
if [ "$sha_a" != "$sha_b" ] || [ "$b3_a" != "$b3_b" ]; then
  log "build A: sha256=$sha_a blake3=$b3_a"
  log "build B: sha256=$sha_b blake3=$b3_b"
  die "runner is NOT reproducible: build A != build B"
fi

# --- (5) leakage scan: no build-environment-specific bytes in the reproducible artifact ----------
# The artifacts are byte-identical, so anything embedded here is COMMON to both builds (same machine,
# user, host) and would NOT be caught by the A-vs-B diff — this is the check for it. `strings -a`
# scans the whole file; grep for each forbidden literal (build roots, $HOME, $USER, hostname) and an
# RFC3339/date-like timestamp regex.
strings_out="$(strings -a "$work/artifact.a" 2>/dev/null || true)"
scan_forbidden() {
  local label="$1" pat="$2" mode="$3" hits
  [ -n "$pat" ] || return 0
  if [ "$mode" = F ]; then
    hits="$(printf '%s\n' "$strings_out" | grep -F -- "$pat" | head -n 3 || true)"
  else
    hits="$(printf '%s\n' "$strings_out" | grep -E -- "$pat" | head -n 3 || true)"
  fi
  if [ -n "$hits" ]; then
    log "leakage[$label] sample: $(printf '%s' "$hits" | tr '\n' '|')"
    die "reproducibility leakage: artifact embeds build-environment-specific bytes"
  fi
}
scan_forbidden "root-a" "$A_ABS" F
scan_forbidden "root-b" "$B_ABS" F
scan_forbidden "home"   "${HOME:-}" F
scan_forbidden "user"   "${USER:-}" F
hn="$(hostname 2>/dev/null || true)"
scan_forbidden "hostname" "$hn" F
scan_forbidden "timestamp" '[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}:[0-9]{2}' E

log "reproducible artifact verified (arch=$ARCH): sha256=$sha_a blake3=$b3_a; no build-env leakage"

# --- (6) machine-readable attestation block to STDOUT --------------------------------------------
printf '# b0-final double-build reproducibility attestation (v1)\n'
printf 'arch=%s\n' "$ARCH"
printf 'build_git_sha=%s\n' "$EXPECT_SHA"
printf 'artifact_sha256=%s\n' "$sha_a"
printf 'artifact_blake3=%s\n' "$b3_a"
printf 'root_a=%s\n' "$A_ABS"
printf 'root_b=%s\n' "$B_ABS"
printf 'start_a=%s\n' "$start_a"
printf 'end_a=%s\n' "$end_a"
printf 'start_b=%s\n' "$start_b"
printf 'end_b=%s\n' "$end_b"
printf 'reproducible=true\n'
