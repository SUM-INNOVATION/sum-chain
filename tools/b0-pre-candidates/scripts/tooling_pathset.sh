#!/usr/bin/env bash
# Canonical MEASUREMENT-TOOLING path-set inventory + content digest (two-root model).
#
# Prints, on success, the canonical path-set PREIMAGE (the exact manifest bytes hashed to produce the
# digest) to a file (if --out is given) and the 64-hex path-set digest to STDOUT (diagnostics to
# STDERR). The manifest is one line per included file, `"<file_blake3_hex>  <relpath>\n"`, LC_ALL=C
# sorted by relpath; `--out` writes EXACTLY those bytes so `BLAKE3(DOMAIN‖NUL‖<--out bytes>)` reproduces
# the digest — i.e. the file is the canonical preimage, carrying every included file's content hash, not
# a bare path list. The validation bundle embeds this file as `tooling-inventory.txt`, which is why the
# bundle content-address transitively binds every tooling file's bytes.
#
# The digest is the exact value Commit B records in
# `b0_pre_validator::tooling_authority::RATIFIED_MEASUREMENT_TOOLING_PATHSET_BLAKE3` and the venue
# re-derives at run time as `recomputed_pathset_blake3`.
#
# Digest formula (matches `tooling_authority::recompute_pathset_digest`):
#   manifest = for each inventory relpath in LC_ALL=C sort order: "<file_blake3_hex>  <relpath>\n"
#   digest   = BLAKE3( "b0-final-measurement-tooling-pathset/v1\0" || manifest )
#
# The path set is every git-tracked REVIEWED tooling byte that can affect identity orchestration,
# runner construction, protobuf provisioning, host provenance, measurement execution, firewall/RSS
# capture, raw-fact production, result assembly, and validator/independent verification — EXCLUDING
# exactly one file: `tools/b0-pre-validator/src/tooling_authority.rs`, the Commit-B authority-binding
# surface, so Commit B's edit there cannot change the digest it records (documented, non-circular).
#
# Fail-closed refusals: missing path, symlink, non-regular file, an UNTRACKED executable/helper under
# the tooling dirs, a DIRTY tooling root (with --require-clean), and a git-unavailable tree.
set -euo pipefail

DOMAIN='b0-final-measurement-tooling-pathset/v1'
EXCLUDE='tools/b0-pre-validator/src/tooling_authority.rs'
die() { printf 'TOOLING-PATHSET-REFUSED: %s\n' "$*" >&2; exit 8; }
log() { printf '%s\n' "$*" >&2; }

ROOT="" OUT="" REQUIRE_CLEAN=0
while [ $# -gt 0 ]; do
  case "$1" in
    --root) [ $# -ge 2 ] || die "--root needs a value"; [ -z "$ROOT" ] || die "--root given twice"; ROOT="$2"; shift 2 ;;
    --out) [ $# -ge 2 ] || die "--out needs a value"; [ -z "$OUT" ] || die "--out given twice"; OUT="$2"; shift 2 ;;
    --require-clean) REQUIRE_CLEAN=1; shift ;;
    *) die "unknown/positional argument: $1" ;;
  esac
done
[ -n "$ROOT" ] || ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
command -v git >/dev/null 2>&1 || die "git not available"
command -v b3sum >/dev/null 2>&1 || die "b3sum not available"
git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1 || die "not a git work tree: $ROOT"

# The tooling globs (git pathspecs). Kept in sync with the reviewed tooling graph.
GLOBS=(
  'tools/b0-pre-candidates/scripts/*.sh'
  'tools/b0-pre-candidates/scripts/*.py'
  'tools/b0-pre-candidates/scripts/tests/*.sh'
  'tools/b0-pre-host-provenance/src/*.rs' 'tools/b0-pre-host-provenance/Cargo.toml'
  'tools/b0-pre-measure-core/src/*.rs'    'tools/b0-pre-measure-core/Cargo.toml'
  'tools/b0-pre-measure-sp1/src/*.rs'     'tools/b0-pre-measure-sp1/Cargo.toml'
  'tools/b0-pre-measure-risc0/src/*.rs'   'tools/b0-pre-measure-risc0/Cargo.toml'
  # The RISC Zero build script canonicalizes the embedded guest's methods.rs (§G runner
  # path-independence); it materially affects the runner binary identity, so it is reviewed tooling.
  'tools/b0-pre-measure-risc0/build.rs'
  'tools/b0-pre-validator/src/*.rs' 'tools/b0-pre-validator/src/bin/*.rs' 'tools/b0-pre-validator/src/schema/*.rs' 'tools/b0-pre-validator/src/venue/*.rs' 'tools/b0-pre-validator/Cargo.toml'
  'tools/b0-pre-independent/src/*.rs' 'tools/b0-pre-independent/src/bin/*.rs' 'tools/b0-pre-independent/Cargo.toml'
  # Durable, repository-carried protobuf include authority (mandatory content-addressed input).
  'docs/b0-pre/venue/protobuf-include-authority/INVENTORY.json'
  'docs/b0-pre/venue/protobuf-include-authority/CONTENT-ADDRESS.txt'
  'docs/b0-pre/venue/protobuf-include-authority/include/google/protobuf/empty.proto'
)

# Refuse an untracked executable/helper anywhere under the tooling script dir (a smuggled helper).
untracked="$(git -C "$ROOT" ls-files --others --exclude-standard -- 'tools/b0-pre-candidates/scripts/' || true)"
[ -z "$untracked" ] || die "untracked tooling helper present under scripts/: $(printf '%s' "$untracked" | tr '\n' ' ')"

# Optionally refuse a dirty tooling root (venue runs from a clean ratified checkout).
if [ "$REQUIRE_CLEAN" = "1" ]; then
  dirty="$(git -C "$ROOT" status --porcelain -- "${GLOBS[@]}" || true)"
  [ -z "$dirty" ] || die "dirty tooling root (uncommitted changes): $(printf '%s' "$dirty" | tr '\n' ' ')"
fi

# Canonical sorted inventory (git-tracked, minus the excluded authority file).
inventory="$(git -C "$ROOT" ls-files -- "${GLOBS[@]}" | grep -vxF "$EXCLUDE" | LC_ALL=C sort)"
[ -n "$inventory" ] || die "empty tooling inventory (globs matched nothing)"

# Build the manifest, fail-closed per path.
manifest=""
while IFS= read -r rel; do
  [ -n "$rel" ] || continue
  abs="$ROOT/$rel"
  [ -e "$abs" ] || die "inventory path missing: $rel"
  [ -L "$abs" ] && die "inventory path is a symlink (refused): $rel"
  [ -f "$abs" ] || die "inventory path is not a regular file: $rel"
  bh="$(b3sum "$abs" | awk '{print $1}')"
  [ ${#bh} -eq 64 ] || die "bad blake3 for $rel"
  manifest="${manifest}${bh}  ${rel}"$'\n'
done <<< "$inventory"

# digest = BLAKE3( domain || NUL || manifest ).
digest="$( { printf '%s\0' "$DOMAIN"; printf '%s' "$manifest"; } | b3sum | awk '{print $1}')"
[ ${#digest} -eq 64 ] || die "digest computation failed"

count="$(printf '%s\n' "$inventory" | grep -c . || true)"
log "tooling path-set: $count files, digest $digest (excluded 1: $EXCLUDE)"
if [ -n "$OUT" ]; then
  # Write the canonical PREIMAGE (the exact manifest bytes hashed above), not a bare path list, so the
  # file carries every included file's content hash and `BLAKE3(DOMAIN‖NUL‖<file>)` reproduces $digest.
  printf '%s' "$manifest" > "$OUT" || die "write inventory manifest to $OUT failed"
  log "wrote inventory manifest ($count lines) to $OUT"
fi
printf '%s\n' "$digest"
