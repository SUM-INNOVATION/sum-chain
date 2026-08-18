#!/usr/bin/env bash
# DOUBLE clean build + reproducibility gate for the SP1/RISC0 runner under the CANONICAL rustc
# path-independence recipe, retaining the EXACT bytes both verifiers need to re-prove path-independence
# from scratch. The runner source is MATERIALIZED at the fixed ratified build path (/b0/tooling) and
# built THERE both times, from two GENUINELY DIFFERENT original checkout roots, with two distinct
# CARGO_HOME / target roots remapped (--remap-path-prefix, via CARGO_ENCODED_RUSTFLAGS) to the FIXED
# destinations /b0/cargo, /b0/target. Building at one canonical source path makes rustc's package
# `-Cmetadata`/StableCrateId (which encodes the absolute source path and which --remap-path-prefix
# CANNOT neutralize) universal, so the two runner binaries — and, for RISC Zero, the two embedded guests
# — are BYTE-IDENTICAL: the proof the runner is independent of where the checkout lived and of the
# CARGO_HOME/target paths. The distinct original roots are retained + leakage-refused and PROVEN not to
# affect the bytes (they never reach the compiler); the source is NOT remapped (canonical by construction).
#
# There is NO opaque build command. The canonical build argv is CONSTRUCTED and enforced here from typed
# inputs, and RETAINED verbatim (vector of exact arguments): the candidate's runner is built with
#   <cargo> [+<toolchain>] build --release --locked --features real-backend --manifest-path <manifest>
# with BUILD_GIT_SHA (measured source), SOURCE_DATE_EPOCH=0, and an explicit B0_VENUE_EMBED state. No
# structural recipe id may claim --locked/--release/--features real-backend unless THIS executed argv
# carries them — it always does, and the exact argv travels in the recipe facts.
#
# Retained per build (A and B), for import-time re-proof:
#   * the exact CARGO_ENCODED_RUSTFLAGS bytes (unit separators included), original-root/CARGO_HOME/target;
#   * the shared canonical build path (== the ratified /b0/tooling), where both builds actually ran;
#   * the exact per-invocation rustc --remap-path-prefix argv the transparent wrapper recorded (2 remaps);
#   * the runner SHA-256 + BLAKE3, and (RISC0) the embedded guest image id + canonical methods.rs digest;
#   * distinct-original-root + chronological evidence; a leakage refused-set that CONTAINS every A/B
#     original / CARGO_HOME / target root + the evidence root, cross-checkable against the recipe.
#
# Usage:
#   double_build_runner.sh --candidate <sp1|risc0> --manifest <relpath> --artifact <relpath-under-target>
#       --src-a <dir> --src-b <dir> --root-a <dir> --root-b <dir> --canonical-build-path <dir>
#       --arch <x86_64|aarch64> --expect-build-git-sha <40-hex> --wrapper <path>
#       --per-arch-toolchain-identity <64-hex> --embed <0|1> --recipe-out <path>
#       [--cargo <path>] [--toolchain <name>] [--risc0-home <dir>]
# --src-a/--src-b are the two DISTINCT original checkout roots (their content must be identical; only
# their PATHS differ). --canonical-build-path is the ratified build path both are materialized at.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib.sh
. "$HERE/lib.sh"
# Restore this script's refusal contract (lib.sh installs its own die/note); lib.sh's recipe helpers
# only `echo >&2; return 1`, so they compose cleanly with this die.
die() { printf 'DOUBLE-BUILD-REFUSED: %s\n' "$*" >&2; exit 7; }
log() { printf '%s\n' "$*" >&2; }
require_cmd() { command -v "$1" >/dev/null 2>&1 || die "required command '$1' not found on PATH"; }

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
  else die "no sha256 tool (sha256sum / shasum) available"; fi
}
blake3_file() { command -v b3sum >/dev/null 2>&1 || die "no blake3 tool (b3sum) available"; b3sum "$1" | awk '{print $1}'; }
blake3_str()  { printf '%s' "$1" | b3sum | awk '{print $1}'; }
to_hex()      { od -An -v -tx1 "$1" | tr -d ' \n'; }

# --- explicit typed flags (no positional / env args; unknown / extra / missing / dup => die) -------
CAND=""; MANIFEST=""; ARTIFACT=""; SRC_A=""; SRC_B=""; ROOT_A=""; ROOT_B=""; CANON_BUILD=""; ARCH=""; EXPECT_SHA=""
WRAPPER=""; TOOLCHAIN_IDENTITY=""; EMBED=""; RECIPE_OUT=""; CARGO="cargo"; TOOLCHAIN=""; RISC0_HOME_IN=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --candidate) [ "$#" -ge 2 ] || die "--candidate requires a value"; [ -z "$CAND" ] || die "duplicate --candidate"; CAND="$2"; shift 2 ;;
    --manifest)  [ "$#" -ge 2 ] || die "--manifest requires a value"; [ -z "$MANIFEST" ] || die "duplicate --manifest"; MANIFEST="$2"; shift 2 ;;
    --artifact)  [ "$#" -ge 2 ] || die "--artifact requires a value"; [ -z "$ARTIFACT" ] || die "duplicate --artifact"; ARTIFACT="$2"; shift 2 ;;
    --src-a)     [ "$#" -ge 2 ] || die "--src-a requires a value"; [ -z "$SRC_A" ] || die "duplicate --src-a"; SRC_A="$2"; shift 2 ;;
    --src-b)     [ "$#" -ge 2 ] || die "--src-b requires a value"; [ -z "$SRC_B" ] || die "duplicate --src-b"; SRC_B="$2"; shift 2 ;;
    --root-a)    [ "$#" -ge 2 ] || die "--root-a requires a value"; [ -z "$ROOT_A" ] || die "duplicate --root-a"; ROOT_A="$2"; shift 2 ;;
    --root-b)    [ "$#" -ge 2 ] || die "--root-b requires a value"; [ -z "$ROOT_B" ] || die "duplicate --root-b"; ROOT_B="$2"; shift 2 ;;
    --canonical-build-path) [ "$#" -ge 2 ] || die "--canonical-build-path requires a value"; [ -z "$CANON_BUILD" ] || die "duplicate --canonical-build-path"; CANON_BUILD="$2"; shift 2 ;;
    --arch)      [ "$#" -ge 2 ] || die "--arch requires a value"; [ -z "$ARCH" ] || die "duplicate --arch"; ARCH="$2"; shift 2 ;;
    --expect-build-git-sha) [ "$#" -ge 2 ] || die "--expect-build-git-sha requires a value"; [ -z "$EXPECT_SHA" ] || die "duplicate --expect-build-git-sha"; EXPECT_SHA="$2"; shift 2 ;;
    --wrapper)   [ "$#" -ge 2 ] || die "--wrapper requires a value"; [ -z "$WRAPPER" ] || die "duplicate --wrapper"; WRAPPER="$2"; shift 2 ;;
    --per-arch-toolchain-identity) [ "$#" -ge 2 ] || die "--per-arch-toolchain-identity requires a value"; [ -z "$TOOLCHAIN_IDENTITY" ] || die "duplicate --per-arch-toolchain-identity"; TOOLCHAIN_IDENTITY="$2"; shift 2 ;;
    --embed)     [ "$#" -ge 2 ] || die "--embed requires a value"; [ -z "$EMBED" ] || die "duplicate --embed"; EMBED="$2"; shift 2 ;;
    --recipe-out)[ "$#" -ge 2 ] || die "--recipe-out requires a value"; [ -z "$RECIPE_OUT" ] || die "duplicate --recipe-out"; RECIPE_OUT="$2"; shift 2 ;;
    --cargo)     [ "$#" -ge 2 ] || die "--cargo requires a value"; CARGO="$2"; shift 2 ;;
    --toolchain) [ "$#" -ge 2 ] || die "--toolchain requires a value"; TOOLCHAIN="$2"; shift 2 ;;
    --risc0-home)[ "$#" -ge 2 ] || die "--risc0-home requires a value"; RISC0_HOME_IN="$2"; shift 2 ;;
    *) die "unknown/extra argument: $1" ;;
  esac
done
[ -n "$CAND" ] || die "--candidate is required"
case "$CAND" in sp1|risc0) ;; *) die "--candidate must be sp1|risc0 (got '$CAND')" ;; esac
for req in MANIFEST ARTIFACT SRC_A SRC_B ROOT_A ROOT_B CANON_BUILD ARCH EXPECT_SHA WRAPPER TOOLCHAIN_IDENTITY EMBED RECIPE_OUT; do
  [ -n "${!req}" ] || die "a required flag is missing (--${req})"
done
case "$ARCH" in x86_64|aarch64) ;; *) die "--arch must be x86_64|aarch64 (got '$ARCH')" ;; esac
case "$EMBED" in 0|1) ;; *) die "--embed must be 0|1 (B0_VENUE_EMBED state) (got '$EMBED')" ;; esac
printf '%s' "$EXPECT_SHA" | grep -Eq '^[0-9a-f]{40}$' || die "--expect-build-git-sha must be exactly 40 lowercase hex: '$EXPECT_SHA'"
printf '%s' "$TOOLCHAIN_IDENTITY" | grep -Eq '^[0-9a-f]{64}$' || die "--per-arch-toolchain-identity must be exactly 64 lowercase hex"
[ "$CAND" = risc0 ] && [ "$EMBED" = 1 ] && [ -z "$RISC0_HOME_IN" ] && die "--risc0-home is required for a RISC0 real embed (--embed 1)"

# GAP 1 (literal pin, pure-string gate — runs BEFORE any filesystem check or mutation): the canonical
# build path is PINNED to the exact literal /b0/tooling (the ratified cross-venue build location the
# validator also pins). This rejects a trailing slash, "/b0/tooling/..", "/b0//tooling", any relative
# path, and every other absolute path — before a single `rm` runs. The filesystem symlink/alias defence
# (that /b0 and /b0/tooling are real, not aliased) runs later, under the exclusive lock, before cleanup.
CANON_REQUIRED='/b0/tooling'
[ "$CANON_BUILD" = "$CANON_REQUIRED" ] \
  || die "--canonical-build-path must be EXACTLY $CANON_REQUIRED (got '$CANON_BUILD')"

require_cmd cmp; require_cmd strings; require_cmd b3sum; require_cmd date; require_cmd python3; require_cmd readlink; require_cmd od

WRAPPER_ABS="$(readlink -f "$WRAPPER" 2>/dev/null || true)"
[ -n "$WRAPPER_ABS" ] && [ -f "$WRAPPER_ABS" ] || die "--wrapper does not name a regular file: $WRAPPER"
[ -x "$WRAPPER_ABS" ] || die "--wrapper is not executable: $WRAPPER_ABS"
WRAPPER_B3="$(blake3_file "$WRAPPER_ABS")"

# --- ORIGINAL checkout roots: canonical, distinct (genuine distinction; NEVER compiler-visible) ----
# --src-a/--src-b are two checkouts of the SAME content at DIFFERENT absolute paths. Neither path
# reaches the compiler (both are materialized at the canonical build path below and built there); they
# are retained as provenance + leakage-refused and proven not to affect the runner bytes.
SRC_A_CANON="$(b0_canonicalize_root src-a "$SRC_A")" || die "--src-a is not a valid original checkout root"
SRC_B_CANON="$(b0_canonicalize_root src-b "$SRC_B")" || die "--src-b is not a valid original checkout root"
[ "$SRC_A_CANON" != "$SRC_B_CANON" ] \
  || die "--src-a and --src-b canonicalize to the SAME original root ($SRC_A_CANON); refusing a distinction test that distinguishes nothing"

# GAP 3 (origin authentication): distinct PATHS are not enough — prove A and B are the SAME build inputs
# via a full-build-input manifest (every file's relpath/mode/size/content-hash; symlinks/devices/traversal
# refused; covers Cargo manifests+locks etc. outside the 164-file tooling set). The materialization checks
# (below, per build) then prove each canonical-path copy reproduced its origin, giving the 4-way equality
#   origin_A == origin_B == materialized_A == materialized_B  — the addresses are bound in the proof.
SRC_A_MANIFEST_ADDR="$(b0_source_manifest_addr "$SRC_A_CANON")" \
  || die "--src-a is not a clean build-input tree (non-regular entry, control char, or traversal)"
SRC_B_MANIFEST_ADDR="$(b0_source_manifest_addr "$SRC_B_CANON")" \
  || die "--src-b is not a clean build-input tree (non-regular entry, control char, or traversal)"
[ "$SRC_A_MANIFEST_ADDR" = "$SRC_B_MANIFEST_ADDR" ] \
  || die "--src-a and --src-b have DIFFERENT build-input manifests ($SRC_A_MANIFEST_ADDR != $SRC_B_MANIFEST_ADDR); the origins are not the same content"

for r in "$ROOT_A" "$ROOT_B"; do [ ! -L "$r" ] || die "build root is a symlink (refused): $r"; done
prepare_root() {
  local r="$1" name="$2"
  if [ -e "$r" ]; then
    [ ! -L "$r" ] || die "$name is a symlink (refused): $r"
    [ -d "$r" ] || die "$name exists and is not a directory: $r"
    [ -z "$(ls -A "$r" 2>/dev/null)" ] || die "$name must be EMPTY (single-use clean build root): $r"
  else mkdir -p "$r" || die "cannot create $name: $r"; fi
}
prepare_root "$ROOT_A" "--root-a"; prepare_root "$ROOT_B" "--root-b"
A_ABS="$(cd "$ROOT_A" && pwd -P)"; B_ABS="$(cd "$ROOT_B" && pwd -P)"
[ "$A_ABS" != "$B_ABS" ] || die "--root-a and --root-b must be DISTINCT"
case "$B_ABS/" in "$A_ABS"/*) die "--root-b nested under --root-a" ;; esac
case "$A_ABS/" in "$B_ABS"/*) die "--root-a nested under --root-b" ;; esac
CARGO_A="$A_ABS/cargo"; TARGET_A="$A_ABS/target"; CARGO_B="$B_ABS/cargo"; TARGET_B="$B_ABS/target"
mkdir -p "$CARGO_A" "$TARGET_A" "$CARGO_B" "$TARGET_B"
# CANON_ABS is set below (under the lock); the trap is a BEST-EFFORT backstop for early exits — the
# SUCCESS path uses the explicit fail-hard cleanup in run_one (GAP 5), and the GAP 5 failure path
# `trap - EXIT`s to PRESERVE the diagnostics under $work.
CANON_ABS=""
work="$(mktemp -d)"; trap 'rm -rf "$work"; [ -n "${CANON_ABS:-}" ] && rm -rf "$CANON_ABS"' EXIT
EVID_A="$work/evid-a"; EVID_B="$work/evid-b"; mkdir -p "$EVID_A" "$EVID_B"

# --- canonical, enforced, RETAINED build argv (exact vector) --------------------------------------
CARGO_IDENT="$CARGO"; [ -n "$TOOLCHAIN" ] && CARGO_IDENT="$CARGO +$TOOLCHAIN"
declare -a ARGV=("$CARGO"); [ -n "$TOOLCHAIN" ] && ARGV+=("+$TOOLCHAIN")
ARGV+=(build --release --locked --features real-backend --manifest-path "$MANIFEST")
# The argv MUST carry the reproducibility-relevant flags; construct-then-assert (never claim unproven).
_argvline=" ${ARGV[*]} "
for need in ' build ' ' --release ' ' --locked ' ' --features real-backend ' " --manifest-path $MANIFEST "; do
  case "$_argvline" in *"$need"*) ;; *) die "canonical argv missing required token: '$need'" ;; esac
done

# Two remaps per side (cargo-home, target); the SOURCE is NOT remapped (canonical by construction).
ENC_A="$(b0_canonical_encoded_rustflags "$CARGO_A" "$TARGET_A")" || die "cannot build canonical encoded rustflags for build A"
ENC_B="$(b0_canonical_encoded_rustflags "$CARGO_B" "$TARGET_B")" || die "cannot build canonical encoded rustflags for build B"
b0_refuse_ambient_rustflags "$ENC_A" || die "ambient rustflags refused"
[ "$ENC_A" != "$ENC_B" ] || die "builds A and B present identical CARGO_ENCODED_RUSTFLAGS; distinct cargo/target roots required"

# --- CANONICAL build path (/b0/tooling): the SHARED materialization boundary — LOCKED, PINNED, and the
# location where BOTH builds' source is materialized + compiled. Building at one fixed absolute path
# makes rustc's package -Cmetadata/StableCrateId universal — what makes the runner byte-identical across
# the distinct original roots. Placed here so the fast input-validation refusals run first; the exclusive
# lock is still acquired BEFORE the first canonical-path filesystem check or mutation (both below).
command -v flock >/dev/null 2>&1 || die "flock is required to hold the exclusive canonical-path lock (install util-linux); refusing"
CANON_PARENT="$(dirname "$CANON_REQUIRED")"   # /b0
# The parent must already exist as a REAL directory (venue/CI provisions it) — not a symlink/alias — so
# neither the lock nor the build path can be redirected under us.
[ -d "$CANON_PARENT" ] || die "canonical parent $CANON_PARENT does not exist; provision it first: 'sudo mkdir -p $CANON_PARENT && sudo chown \$(id -un) $CANON_PARENT'"
[ ! -L "$CANON_PARENT" ] || die "canonical parent $CANON_PARENT is a symlink (refused)"
[ "$(readlink -f "$CANON_PARENT")" = "$CANON_PARENT" ] || die "canonical parent $CANON_PARENT resolves elsewhere (alias refused)"

# GAP 2: acquire a FIXED exclusive lock BEFORE the first canonical-path filesystem check or mutation, and
# hold it (FD 9) through cleanup after build B. Non-blocking: refuse IMMEDIATELY if another candidate/
# operator run holds it — never wait silently forever.
LOCKFILE="$CANON_PARENT/.b0-tooling.lock"
exec 9>"$LOCKFILE" || die "cannot open the canonical-path lock file $LOCKFILE"
flock -n 9 || die "another run holds the canonical-path lock ($LOCKFILE); refusing (no silent wait)"

# GAP 1 (filesystem alias defence, under the lock, BEFORE any deletion): the pinned literal itself must
# not be a symlink or resolve elsewhere.
if [ -e "$CANON_REQUIRED" ]; then
  [ ! -L "$CANON_REQUIRED" ] || die "$CANON_REQUIRED is a symlink (refused)"
  [ -d "$CANON_REQUIRED" ] || die "$CANON_REQUIRED exists and is not a directory (refused)"
  [ "$(readlink -f "$CANON_REQUIRED")" = "$CANON_REQUIRED" ] || die "$CANON_REQUIRED resolves elsewhere (alias refused)"
fi
CANON_ABS="$CANON_REQUIRED"   # the PINNED literal (never operator-canonicalized to some other path)
for r in "$SRC_A_CANON" "$SRC_B_CANON" "$A_ABS" "$B_ABS" "$CARGO_A" "$TARGET_A" "$CARGO_B" "$TARGET_B" "$work"; do
  [ "$CANON_ABS" != "$r" ] || die "canonical build path coincides with a root: $CANON_ABS"
  case "$CANON_ABS/" in "$r"/*) die "canonical build path nested under a root: $r" ;; esac
  case "$r/" in "$CANON_ABS"/*) die "a root is nested under the canonical build path: $r" ;; esac
done
# Start from a clean, ABSENT canonical path (run_one materializes it fresh per build under the held lock).
rm -rf "$CANON_ABS" || die "cannot clean the canonical build path $CANON_ABS"

# --- RISC0 embedded-guest identity from a build's OUT_DIR methods.rs (canonical form) --------------
# image id from `..._ID: [u32; 8] = [...]` (packed LE, 64-hex); methods.rs digest binds the canonical
# include form + the id. For a stub build (embed=0) the guest is empty -> zero id, empty-elf digest.
guest_identity() { # <target_dir> ; prints "<image_id_hex64> <methods_blake3_64>"
  [ "$CAND" = risc0 ] || { printf '%s %s\n' "$(printf '0%.0s' $(seq 64))" "$(printf '' | b3sum | awk '{print $1}')"; return; }
  local td="$1" mrs
  mrs="$(find "$td/release/build" -maxdepth 3 -path '*b0-pre-measure-risc0*/out/methods.rs' 2>/dev/null | LC_ALL=C sort | head -1)"
  if [ -z "$mrs" ] || [ ! -f "$mrs" ]; then printf '%s %s\n' "$(printf '0%.0s' $(seq 64))" "$(printf '' | b3sum | awk '{print $1}')"; return; fi
  python3 - "$mrs" <<'PY'
import re, struct, subprocess, sys
t = open(sys.argv[1]).read()
m = re.search(r'_ID:\s*\[u32;\s*8\]\s*=\s*\[([^\]]*)\]', t)
vals = []
if m:
    inner = m.group(1).strip()
    def to_int(x):
        x = re.sub(r'(u32|usize|i32)$', '', x.strip())
        return int(x, 0)
    try:
        if ';' in inner:            # `[<value>u32; 8]` repeat form (the CI stub -> all-zeros id)
            vals = [to_int(inner.split(';', 1)[0])] * 8
        else:                       # `[n, n, ...]` plain form (embed_methods() real id)
            vals = [to_int(x) for x in inner.split(',') if x.strip()]
    except ValueError:
        vals = []
img = (b''.join(struct.pack('<I', v & 0xffffffff) for v in vals).hex()) if len(vals) == 8 else '0' * 64
mb = subprocess.run(['b3sum', sys.argv[1]], capture_output=True, text=True).stdout.split()[0]
print(img, mb)
PY
}

# --- two clean, wall-clock-separated builds at the CANONICAL build path -----------------------------
# Each build MATERIALIZES its distinct original root at the single canonical build path and compiles
# THERE (so the compiler-visible source path is identical for A and B), with that build's distinct
# CARGO_HOME/target (remapped). The original root's path never reaches the compiler.
declare -A RUN_SHA RUN_B3 G_IMG G_MB T_START T_END MAT_ADDR
run_one() {
  local tag="$1" src="$2" cargo="$3" target="$4" enc="$5" evid="$6" origin_addr="$7" last mat_addr
  local -a envv=(BUILD_GIT_SHA="$EXPECT_SHA" SOURCE_DATE_EPOCH=0 B0_VENUE_EMBED="$EMBED"
    CARGO_HOME="$cargo" CARGO_TARGET_DIR="$target" CARGO_ENCODED_RUSTFLAGS="$enc"
    RUSTC_WRAPPER="$WRAPPER_ABS" B0_RUSTC_EVIDENCE_DIR="$evid")
  [ "$CAND" = risc0 ] && [ "$EMBED" = 1 ] && envv+=(RISC0_HOME="$RISC0_HOME_IN")
  # Materialize this build's source at the canonical build path (fresh copy; mode-preserving; $src only).
  rm -rf "$CANON_ABS" || die "cannot clean canonical build path: $CANON_ABS"
  cp -Rp "$src" "$CANON_ABS" || die "cannot materialize $tag source at canonical build path: $src -> $CANON_ABS"
  # GAP 3 (materialization fidelity): the copy must reproduce this origin EXACTLY (also proves the fresh
  # rm removed any stale/mutated file a prior run may have left) — else refuse before compiling.
  mat_addr="$(b0_source_manifest_addr "$CANON_ABS")" \
    || die "build $tag: materialized tree at $CANON_ABS is not clean (non-regular entry / traversal)"
  [ "$mat_addr" = "$origin_addr" ] \
    || die "build $tag: materialized manifest $mat_addr != origin manifest $origin_addr (materialization not faithful / stale content)"
  MAT_ADDR[$tag]="$mat_addr"
  T_START[$tag]="$(date +%s)"
  if ! (cd "$CANON_ABS" && env -u RUSTFLAGS -u CARGO_BUILD_RUSTFLAGS "${envv[@]}" "${ARGV[@]}" >/dev/null 2>&1); then
    die "clean build $tag FAILED (canonical_src=$CANON_ABS target=$target argv='${ARGV[*]}')"
  fi
  T_END[$tag]="$(date +%s)"
  last="$target/$ARTIFACT"
  [ -f "$last" ] || die "build $tag did not produce the expected artifact: $last"
  cp -f "$last" "$work/artifact.$tag" || die "cannot preserve build $tag artifact"
  [ -n "$(ls -A "$evid" 2>/dev/null)" ] || die "build $tag produced no rustc invocation evidence (wrapper never ran / recipe not applied)"
  RUN_SHA[$tag]="$(sha256_file "$work/artifact.$tag")"
  RUN_B3[$tag]="$(blake3_file "$work/artifact.$tag")"
  read -r "G_IMG[$tag]" "G_MB[$tag]" <<<"$(guest_identity "$target")"
  # GAP 5: authoritative cleanup — a failure to remove the canonical source FAILS the run (never leave
  # authoritative source behind while reporting success); `trap - EXIT` preserves the diagnostics ($work,
  # which holds the retained artifacts + rustc-invocation evidence, all OUTSIDE the canonical path).
  if ! rm -rf "$CANON_ABS"; then
    trap - EXIT
    die "build $tag: FAILED to remove canonical source $CANON_ABS; authoritative source may remain. Diagnostics preserved at $work"
  fi
}
run_one a "$SRC_A_CANON" "$CARGO_A" "$TARGET_A" "$ENC_A" "$EVID_A" "$SRC_A_MANIFEST_ADDR"
log "build A done: sha256=${RUN_SHA[a]} blake3=${RUN_B3[a]} guest_img=${G_IMG[a]}"
run_one b "$SRC_B_CANON" "$CARGO_B" "$TARGET_B" "$ENC_B" "$EVID_B" "$SRC_B_MANIFEST_ADDR"
log "build B done: sha256=${RUN_SHA[b]} blake3=${RUN_B3[b]} guest_img=${G_IMG[b]}"

# Separation: build B started only after build A finished; each artifact preserved immediately.
[ "${T_START[b]}" -ge "${T_END[a]}" ] || die "build B started before build A finished; refusing"
[ "${T_END[b]}" -ge "${T_END[a]}" ]   || die "impossible ordering; refusing"

# --- byte-identity: runner A == runner B (and, RISC0, embedded guest A == B) -----------------------
if ! cmp -s "$work/artifact.a" "$work/artifact.b" \
   || [ "${RUN_SHA[a]}" != "${RUN_SHA[b]}" ] || [ "${RUN_B3[a]}" != "${RUN_B3[b]}" ]; then
  # DIAGNOSTIC: surface WHAT differs so a non-reproducibility can be triaged as a path leak (an
  # uncontrolled /b0-input|/b0-build root the recipe failed to remove) vs. an orthogonal source
  # (a build-time timestamp, an embedded absolute path a dependency baked as a VALUE, etc.).
  log "DIAGNOSTIC non-reproducible: first byte diff: $(cmp "$work/artifact.a" "$work/artifact.b" 2>&1 | head -1)"
  strings -a "$work/artifact.a" 2>/dev/null | LC_ALL=C sort -u > "$work/sa" || true
  strings -a "$work/artifact.b" 2>/dev/null | LC_ALL=C sort -u > "$work/sb" || true
  log "DIAGNOSTIC A-only strings that look like a path/date/epoch (sample):"
  comm -23 "$work/sa" "$work/sb" 2>/dev/null | grep -aE '/b0-input|/b0-build|/b0/|[0-9]{4}-[0-9]{2}-[0-9]{2}|[0-9]{9,}' | head -25 | while IFS= read -r l; do log "  A: $l"; done
  log "DIAGNOSTIC B-only strings that look like a path/date/epoch (sample):"
  comm -13 "$work/sa" "$work/sb" 2>/dev/null | grep -aE '/b0-input|/b0-build|/b0/|[0-9]{4}-[0-9]{2}-[0-9]{2}|[0-9]{9,}' | head -25 | while IFS= read -r l; do log "  B: $l"; done
  die "runner is NOT reproducible under the path-independence recipe: build A != build B"
fi
if [ "$CAND" = risc0 ]; then
  [ "${G_IMG[a]}" = "${G_IMG[b]}" ] || die "RISC0 embedded guest image id differs between build A and build B"
  [ "${G_MB[a]}"  = "${G_MB[b]}"  ] || die "RISC0 canonical methods.rs differs between build A and build B"
fi

# --- PATH-PREFIX / PATH-COMPONENT leakage scan (b0_leakage_scan) -----------------------------------
# The guarantee is the ABSENCE of uncontrolled absolute PATH PREFIXES (every A/B source/CARGO_HOME/
# target + evidence + work + HOME + TMPDIR) and of the username/hostname as a PATH COMPONENT — NOT the
# absence of the bare username/hostname as ordinary substrings (prose like "measurement runner" is not
# a leak). The exact-prefix refused set travels in the recipe facts (leakage_refused_prefixes).
strings_out="$(strings -a "$work/artifact.a" 2>/dev/null || true)"
REFUSED_ROOTS=("$SRC_A_CANON" "$SRC_B_CANON" "$CARGO_A" "$CARGO_B" "$TARGET_A" "$TARGET_B" "$EVID_A" "$EVID_B" "$work")
[ -n "${HOME:-}" ] && REFUSED_ROOTS+=("$HOME")
[ -n "${TMPDIR:-}" ] && REFUSED_ROOTS+=("${TMPDIR%/}")
hn="$(hostname 2>/dev/null || true)"
REFUSED_LIST="$(printf '%s\n' "${REFUSED_ROOTS[@]}")"
if hit="$(b0_leakage_scan "$strings_out" "$REFUSED_LIST" "${USER:-}" "$hn")"; then
  : # clean
else
  log "leakage: $hit"; die "reproducibility leakage: artifact embeds an uncontrolled path-prefix/component: $hit"
fi
log "reproducible runner verified (candidate=$CAND arch=$ARCH): blake3=${RUN_B3[a]}; no uncontrolled path-prefix/component leakage"

# --- emit the rich runner-recipe facts JSON (exact bytes for A and B + double-build proof) ---------
ENC_A_HEX="$(printf '%s' "$ENC_A" | od -An -v -tx1 | tr -d ' \n')"
ENC_B_HEX="$(printf '%s' "$ENC_B" | od -An -v -tx1 | tr -d ' \n')"
ARGV_JSON="$(printf '%s\n' "${ARGV[@]}" | python3 -c 'import json,sys; print(json.dumps([l.rstrip("\n") for l in sys.stdin]))')"
# Env retained as an ordered vector (only reproducibility-relevant keys).
ENV_JSON="$(python3 -c 'import json,sys; print(json.dumps([["BUILD_GIT_SHA",sys.argv[1]],["SOURCE_DATE_EPOCH","0"],["B0_VENUE_EMBED",sys.argv[2]]]))' "$EXPECT_SHA" "$EMBED")"
REFUSED_JSON="$(printf '%s\n' "${REFUSED_ROOTS[@]}" | python3 -c 'import json,sys; print(json.dumps(sorted({l.rstrip(chr(10)) for l in sys.stdin if l.strip()})))')"

python3 - "$RECIPE_OUT" "$CAND" "$ARCH" "$MANIFEST" "$ARTIFACT" "$CARGO_IDENT" "$EMBED" \
  "$TOOLCHAIN_IDENTITY" "$WRAPPER_B3" "$ARGV_JSON" "$ENV_JSON" "$REFUSED_JSON" \
  "$SRC_A_CANON" "$CARGO_A" "$TARGET_A" "$ENC_A_HEX" "${RUN_SHA[a]}" "${RUN_B3[a]}" "${G_IMG[a]}" "${G_MB[a]}" "${T_START[a]}" "${T_END[a]}" "$EVID_A" \
  "$SRC_B_CANON" "$CARGO_B" "$TARGET_B" "$ENC_B_HEX" "${RUN_SHA[b]}" "${RUN_B3[b]}" "${G_IMG[b]}" "${G_MB[b]}" "${T_START[b]}" "${T_END[b]}" "$EVID_B" \
  "$work" "$CANON_ABS" \
  "$SRC_A_MANIFEST_ADDR" "${MAT_ADDR[a]}" "$SRC_B_MANIFEST_ADDR" "${MAT_ADDR[b]}" <<'PY' || die "failed to emit runner-recipe facts JSON"
import json, os, sys
a = sys.argv
(out, cand, arch, manifest, artifact, cargo_ident, embed, toolchain, wrapper_b3, argv_json, env_json, refused_json) = a[1:13]
def build(off, orig_addr, mat_addr):
    orig, cargo, target, enc_hex, rsha, rb3, gimg, gmb, ts, te, evid = a[off:off+11]
    invs = []
    for name in sorted(os.listdir(evid)):
        if not name.endswith('.rec'):
            continue
        body = open(os.path.join(evid, name), encoding='utf-8').read()
        kind = ''
        remap_args = []
        for line in body.splitlines():
            if line.startswith('kind='):
                kind = line[5:]
            elif line.startswith('remap_arg='):
                remap_args.append(line[len('remap_arg='):])
        invs.append({'kind': kind, 'remap_args': remap_args, 'record_address': name[:-4]})
    return {
        'original_root': orig, 'cargo_from': cargo, 'target_from': target,
        'encoded_rustflags_hex': enc_hex, 'runner_sha256': rsha, 'runner_blake3': rb3,
        'guest_image_id': gimg, 'guest_methods_blake3': gmb, 'start_unix': int(ts), 'end_unix': int(te),
        'origin_manifest_blake3': orig_addr, 'materialized_manifest_blake3': mat_addr,
        'invocations': invs,
    }
ba = build(13, a[37], a[38]); bb = build(24, a[39], a[40])
doc = {
    'candidate': cand, 'arch': arch, 'manifest_path': manifest, 'artifact_path': artifact,
    'cargo_ident': cargo_ident, 'b0_venue_embed': embed, 'per_arch_toolchain_identity': toolchain,
    'wrapper_blake3': wrapper_b3, 'build_argv': json.loads(argv_json), 'build_env': json.loads(env_json),
    'canonical_build_path': a[36],
    'build_a': ba, 'build_b': bb, 'byte_equal': True,
    'leakage_refused_prefixes': json.loads(refused_json),
    'leakage_permitted_prefixes': ['/b0/cargo', '/b0/target', '/b0/tooling'], 'leakage_clean': True,
    'evidence_root': a[35],
}
if not any(i['kind'] == 'compile' for i in ba['invocations']):
    sys.exit('build A recorded no compile invocation')
if not any(i['kind'] == 'compile' for i in bb['invocations']):
    sys.exit('build B recorded no compile invocation')
# The 4-way source-input authentication (origin A/B, materialized A/B) must all agree.
mans = {ba['origin_manifest_blake3'], bb['origin_manifest_blake3'],
        ba['materialized_manifest_blake3'], bb['materialized_manifest_blake3']}
if len(mans) != 1 or not (len(mans.pop()) == 64):
    sys.exit('source-input manifests are not all equal 64-hex (origin A/B, materialized A/B)')
with open(out, 'w', encoding='utf-8') as f:
    json.dump(doc, f, indent=2)
    f.write('\n')
PY
[ -s "$RECIPE_OUT" ] || die "runner-recipe facts JSON was not written: $RECIPE_OUT"

printf '# b0-final double-build reproducibility + path-independence attestation (v3)\n'
printf 'candidate=%s\narch=%s\nbuild_git_sha=%s\nb0_venue_embed=%s\n' "$CAND" "$ARCH" "$EXPECT_SHA" "$EMBED"
printf 'runner_sha256=%s\nrunner_blake3=%s\n' "${RUN_SHA[a]}" "${RUN_B3[a]}"
printf 'guest_image_id=%s\nguest_methods_blake3=%s\n' "${G_IMG[a]}" "${G_MB[a]}"
printf 'src_a=%s\nsrc_b=%s\nwrapper_blake3=%s\n' "$SRC_A_CANON" "$SRC_B_CANON" "$WRAPPER_B3"
printf 'recipe_facts=%s\nreproducible=true\npath_independent=true\n' "$RECIPE_OUT"
