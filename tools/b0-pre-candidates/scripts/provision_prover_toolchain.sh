#!/usr/bin/env bash
# STAGED, SELF-CONTAINED declarative prover-toolchain provisioner (owner ruling: replaces
# `curl | tar` and `rzup`). It is COPIED verbatim into the curated Docker build context and run
# INSIDE the pinned Debian builder — it therefore sources NO host lib.sh and depends only on
# coreutils + tar (no python/jq). It is the SINGLE implementation of the verified-extraction
# mechanism (tested on the host with crafted archives in tests/verified_extraction.test.sh).
#
# Given a downloaded archive already on disk and the COMPLETE declared member set, in strict order:
#   1. verify the whole-archive SHA-256 BEFORE any extraction;
#   2. enumerate EVERY archive entry and REFUSE symlinks/hardlinks, absolute paths, `..` traversal,
#      duplicate entries, and any regular-file member that is NOT explicitly declared (complete-set
#      validation) — and require every declared member to be present;
#   3. extract ONLY the explicitly declared members;
#   4. verify each member's SIZE and SHA-256 BEFORE chmod/execution;
#   5. place it (isolated verified PATH dir for cargo subcommands; the exact RISC0_SERVER_PATH file
#      for r0vm), chmod 0755, and RE-HASH at the point of use (must still equal the member SHA).
# Fails closed at every mismatch. RISC Zero members are provisioned on x86_64 only (VENUE.md §2).
#
# Usage:
#   provision_prover_toolchain.sh <archive_file> <archive_sha256> <isolated_bin_dir> \
#       <risc0_server_dir> <member_spec>...
# where each <member_spec> = 'member_path:sha256:size_bytes:delivery'  (delivery = isolated|risc0server)
set -euo pipefail

die() { printf 'PROVISION-REFUSED: %s\n' "$*" >&2; exit 4; }

# sha256 of a file, coreutils (Debian) or shasum (host tests). Self-contained (no lib.sh).
sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
  else die "no sha256 tool (sha256sum / shasum) available"; fi
}
is_bare_sha256() { printf '%s' "${1:-}" | grep -Eq '^[0-9a-f]{64}$'; }

archive="${1:-}"; archive_sha="${2:-}"; isolated_dir="${3:-}"; risc0_dir="${4:-}"
shift 4 2>/dev/null || die "usage: provision_prover_toolchain.sh <archive> <sha256> <isolated_dir> <risc0_dir> <member_spec>..."
[ -f "$archive" ] || die "archive file absent: $archive"
is_bare_sha256 "$archive_sha" || die "archive sha256 is not bare 64-hex: $archive_sha"
[ "$#" -ge 1 ] || die "at least one member spec is required"
command -v tar >/dev/null 2>&1 || die "tar not available"

# (1) verify the whole-archive hash BEFORE extraction.
got="$(sha256_file "$archive")"
[ "$got" = "$archive_sha" ] || die "archive sha256 MISMATCH (got $got, want $archive_sha): $archive"

# Parse the declared member set.
declared_paths=""    # newline-separated
for spec in "$@"; do
  mp="${spec%%:*}"; rest="${spec#*:}"
  [ "$mp" != "$spec" ] || die "malformed member spec (need member_path:sha256:size:delivery): $spec"
  case "$mp" in /*|*..*) die "declared member path is unsafe: $mp" ;; esac
  declared_paths="$declared_paths$mp
"
done

# (2) enumerate EVERY entry (verbose, so the type flag is visible). Refuse links/absolute/traversal.
#     GNU + BSD tar both print the type flag as the first char of the mode column; a regular file is
#     '-', a directory 'd', a symlink 'l', a hardlink 'h'. The member name is the LAST field.
listing="$(tar -tvzf "$archive")" || die "cannot list archive members: $archive"
reg_members=""   # newline-separated regular-file member paths
while IFS= read -r line; do
  [ -n "$line" ] || continue
  type_char="$(printf '%s' "$line" | cut -c1)"
  name="$(printf '%s' "$line" | awk '{print $NF}')"
  case "$name" in /*|*..*) die "archive entry has an unsafe path (absolute or ..): $name" ;; esac
  case "$type_char" in
    l|h) die "archive contains a link entry (refused): $name" ;;
    d) : ;;                              # directories are allowed
    *) reg_members="$reg_members$name
" ;;
  esac
done <<EOF
$listing
EOF

# duplicate entries are refused (a name appearing twice among regular files).
dups="$(printf '%s' "$reg_members" | sed '/^$/d' | sort | uniq -d)"
[ -z "$dups" ] || die "archive has duplicate member entries: $(printf '%s' "$dups" | tr '\n' ' ')"

# COMPLETE-SET validation: every regular-file member MUST be a declared member (no unexpected
# member), and every declared member MUST be present.
while IFS= read -r m; do
  [ -n "$m" ] || continue
  printf '%s' "$declared_paths" | grep -Fxq "$m" || die "unexpected archive member (not declared): $m"
done <<EOF
$reg_members
EOF
while IFS= read -r m; do
  [ -n "$m" ] || continue
  printf '%s' "$reg_members" | grep -Fxq "$m" || die "declared member absent from archive: $m"
done <<EOF
$declared_paths
EOF

# (3-5) extract ONLY declared members; verify size+hash BEFORE chmod; place; re-hash at point of use.
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
mkdir -p "$isolated_dir" "$risc0_dir"
for spec in "$@"; do
  mp="${spec%%:*}"; rest="${spec#*:}"
  msha="${rest%%:*}"; rest="${rest#*:}"
  msize="${rest%%:*}"; delivery="${rest#*:}"
  is_bare_sha256 "$msha" || die "member sha256 is not bare 64-hex for $mp: $msha"
  printf '%s' "$msize" | grep -Eq '^[0-9]+$' || die "member size is not a non-negative integer for $mp: $msize"
  case "$delivery" in isolated|risc0server) ;; *) die "delivery must be isolated|risc0server (got '$delivery')" ;; esac

  tar -xzf "$archive" -C "$work" -- "$mp" || die "extraction of declared member '$mp' failed"
  ex="$work/$mp"
  [ -f "$ex" ] || die "extracted member '$mp' is absent"
  # verify SIZE before chmod.
  actual_size="$(wc -c < "$ex" | tr -d ' ')"
  [ "$actual_size" = "$msize" ] || die "member '$mp' SIZE MISMATCH (got $actual_size, want $msize)"
  # verify HASH before chmod.
  actual_sha="$(sha256_file "$ex")"
  [ "$actual_sha" = "$msha" ] || die "member '$mp' sha256 MISMATCH (got $actual_sha, want $msha)"

  exe="$(basename "$mp")"
  case "$delivery" in
    isolated)   dest="$isolated_dir/$exe" ;;
    risc0server) dest="$risc0_dir/$exe" ;;
  esac
  cp "$ex" "$dest"
  chmod 0755 "$dest"
  # RE-HASH immediately after placement (point of use) — must still equal the member SHA.
  pou="$(sha256_file "$dest")"
  [ "$pou" = "$msha" ] || die "point-of-use sha256 MISMATCH for '$exe' after placement (got $pou, want $msha)"
  printf 'provisioned %s -> %s (size+sha verified pre-chmod; point-of-use re-hashed; delivery=%s)\n' "$exe" "$dest" "$delivery"
done
