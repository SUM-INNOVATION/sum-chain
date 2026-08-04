#!/usr/bin/env bash
# STAGED, SELF-CONTAINED verified TREE provisioner for a guest COMPILER toolchain (the SP1
# `succinct-1.94.0-64bit` toolchain, or the RISC Zero `r0.1.91.1` toolchain). Copied verbatim
# into the curated Docker build context and run INSIDE the pinned Debian builder; sources NO host
# lib.sh; depends only on coreutils + tar. Companion of provision_prover_toolchain.sh (that one
# extracts single verified EXECUTABLE members; this one extracts a whole verified toolchain TREE).
#
# Owner constraints honored: NO rzup, NO `cargo risczero build` CLI/guest-builder, NO network
# resolution here (the archive is already on disk), NO inherited ~/.risc0, NO mutable-tag
# resolution. The archive is an OWNER CONTENT PIN — authority is the whole-archive SHA-256
# (verified BEFORE extraction) plus the PROVISIONED_TREE/v1 digest re-verified at point of use by
# the producer. Safe extraction: reject absolute / `..` entries and unsafe symlink targets;
# directories, regular files and hardlinks are allowed (rust toolchains carry hardlinks).
#
# Usage:
#   provision_guest_toolchain.sh <archive> <archive_sha256> <mode> <dest>
#     mode = succinct-toolchain   dest = the toolchain root dir (caller then `rustup toolchain link succinct <dest>`)
#     mode = risc0-home           dest = the isolated RISC0_HOME; the tree lands at
#                                        <dest>/toolchains/v<VER>-rust-<PLATFORM>/, plus settings.toml + .rzup
#   env for risc0-home: R0_TC_VERSION (e.g. 1.91.1), R0_TC_PLATFORM (e.g. x86_64-unknown-linux-gnu)
set -euo pipefail

die() { printf 'GUEST-TOOLCHAIN-REFUSED: %s\n' "$*" >&2; exit 5; }
sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
  else die "no sha256 tool"; fi
}
is_bare_sha256() { printf '%s' "${1:-}" | grep -Eq '^[0-9a-f]{64}$'; }

archive="${1:-}"; archive_sha="${2:-}"; mode="${3:-}"; dest="${4:-}"
[ -f "$archive" ] || die "archive file absent: $archive"
is_bare_sha256 "$archive_sha" || die "archive sha256 is not bare 64-hex: $archive_sha"
[ -n "$dest" ] || die "dest is required"
command -v tar >/dev/null 2>&1 || die "tar not available"

# (1) verify the whole-archive SHA-256 BEFORE any extraction (the content-pin authority).
got="$(sha256_file "$archive")"
[ "$got" = "$archive_sha" ] || die "archive sha256 MISMATCH (got $got, want $archive_sha): $archive"

# (2) enumerate EVERY entry; refuse absolute / `..` traversal. (GNU tar also refuses these, but
#     we check explicitly.) Directories, regular files and hardlinks are allowed; symlink targets
#     are checked after extraction.
listing="$(tar -tzf "$archive")" || die "cannot list archive members: $archive"
while IFS= read -r name; do
  [ -n "$name" ] || continue
  case "$name" in /*|*..*|*/../*) die "archive entry has an unsafe path (absolute or ..): $name" ;; esac
done <<EOF
$listing
EOF

# (3) safe extraction (NEVER -P; do not honor absolute paths) into a temp dir.
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
tar -xzf "$archive" -C "$work" --no-same-owner || die "safe extraction failed: $archive"

# (4) after extraction, refuse any symlink whose target is absolute or escapes via `..`.
unsafe="$(find "$work" -type l -printf '%p -> %l\n' 2>/dev/null | awk '$3 ~ /^\// || $3 ~ /(^|\/)\.\.(\/|$)/ {print}')"
[ -z "$unsafe" ] || die "toolchain contains unsafe symlink(s): $unsafe"

# The rust toolchain archives extract FLAT (bin/ lib/ at the top). Sanity: a compiler must exist.
[ -x "$work/bin/rustc" ] || die "extracted toolchain has no bin/rustc (unexpected layout)"

case "$mode" in
  succinct-toolchain)
    rm -rf "$dest"; mkdir -p "$(dirname "$dest")"
    cp -a "$work" "$dest"
    printf 'provisioned succinct guest toolchain tree -> %s (archive sha256 verified; safe-extracted)\n' "$dest"
    ;;
  risc0-home)
    [ -n "${R0_TC_VERSION:-}" ] || die "risc0-home mode requires R0_TC_VERSION"
    [ -n "${R0_TC_PLATFORM:-}" ] || die "risc0-home mode requires R0_TC_PLATFORM"
    tcdir="$dest/toolchains/v${R0_TC_VERSION}-rust-${R0_TC_PLATFORM}"
    rm -rf "$dest"; mkdir -p "$dest/toolchains"
    cp -a "$work" "$tcdir"
    # Deterministic rzup local config (FIRST-PARTY SCHEMA, reproduced from rzup 0.5.1 source):
    # settings.toml maps component "rust" -> the semver; .rzup is the empty sentinel risc0-build
    # requires. NO rzup was executed to produce these; they point ONLY at the pinned tree above.
    printf '[default_versions]\nrust = "%s"\n' "$R0_TC_VERSION" > "$dest/settings.toml"
    : > "$dest/.rzup"
    printf 'provisioned r0 guest toolchain tree -> %s\n' "$tcdir"
    printf 'wrote deterministic RISC0_HOME config -> %s/settings.toml + %s/.rzup\n' "$dest" "$dest"
    ;;
  *)
    die "mode must be succinct-toolchain|risc0-home (got '$mode')"
    ;;
esac
