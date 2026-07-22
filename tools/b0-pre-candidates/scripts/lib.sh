#!/usr/bin/env bash
# Shared validation / refusal helpers for the B0-PRE candidate build scripts.
#
# Every helper is fail-closed: missing or malformed inputs cause a clear
# NOT_YET_REPRODUCED / refusal exit BEFORE any build, download, or extraction.
# Nothing here installs host-global tooling, starts a daemon, or pushes an image.

set -euo pipefail

die()  { printf 'REFUSED: %s\n' "$*" >&2; exit 2; }
note() { printf '%s\n' "$*"; }
nyr()  { printf 'NOT_YET_REPRODUCED: %s\n' "$*" >&2; exit 3; }

# A full, immutable OCI digest: sha256:<64 lowercase hex>. Rejects mutable tags,
# truncated digests, image IDs, and empty input.
require_full_sha256_digest() {
  local name="$1" val="${2:-}"
  [ -n "$val" ] || nyr "$name is empty; an immutable sha256:<64hex> digest is required"
  case "$val" in
    sha256:*) ;;
    *) die "$name must be a full 'sha256:<64hex>' digest, not a tag or image ID: '$val'" ;;
  esac
  local hex="${val#sha256:}"
  printf '%s' "$hex" | grep -Eq '^[0-9a-f]{64}$' \
    || die "$name is not a full 64-hex sha256 digest (truncation/uppercase/tag rejected): '$val'"
}

# Refuse anything that looks like a placeholder digest.
reject_placeholder() {
  local name="$1" val="${2:-}"
  case "$val" in
    *DEADBEEF*|*deadbeef*|*000000000000*|*TODO*|*PLACEHOLDER*|*xxxx*|*XXXX*)
      die "$name looks like a placeholder, not a real digest: '$val'" ;;
  esac
}

# The build/extract steps must run natively on the requested architecture; no
# emulation. Compares the requested arch to the kernel arch.
require_native_arch() {
  local want="$1" have
  have="$(uname -m)"
  case "$have" in x86_64|amd64) have=x86_64 ;; aarch64|arm64) have=aarch64 ;; esac
  case "$want" in x86_64|amd64) want=x86_64 ;; aarch64|arm64) want=aarch64 ;; esac
  [ "$want" = "$have" ] \
    || die "native $want builder required; this host is $have (emulation is ineligible)"
}

# A Linux OCI-capable builder must be present. Fail-closed if the daemon is down
# or the platform is not Linux.
require_linux_oci_builder() {
  [ "$(uname -s)" = "Linux" ] || die "authoritative builds require a native Linux builder; host is $(uname -s)"
  command -v docker >/dev/null 2>&1 || die "no OCI builder (docker) on PATH"
  docker info >/dev/null 2>&1 || die "OCI builder daemon is not running/reachable"
}

# Minimum free space (GiB) on a given path.
require_free_gib() {
  local path="$1" min="$2" free
  free="$(df -Pg "$path" 2>/dev/null | awk 'NR==2{print $4}')" || free=0
  [ "${free:-0}" -ge "$min" ] || die "need >= ${min}GiB free at $path; only ${free:-0}GiB available"
}

# The candidate must NOT already carry a lock (locks come only from the venue).
require_no_preexisting_lock() {
  local dir="$1"
  [ -f "$dir/Cargo.lock" ] && die "unexpected pre-existing $dir/Cargo.lock; authoritative locks come only from the venue"
  true
}

# Fail-closed if a required command is missing.
require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command '$1' not found on PATH"
}

# Bare 64-hex SHA-256 of stdin, using whichever portable tool is present
# (sha256sum on Linux, shasum on macOS). Used for the OFF-VENUE dry-run producers
# and for hashing local build evidence.
sha256_hex_stdin() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 | awk '{print $1}'
  else
    die "no sha256 tool (sha256sum / shasum) on PATH"
  fi
}

# A deterministic, non-placeholder bare 64-hex value derived from a label. Used by
# the dry-run producers to emit real-SHAPED sample digests off-venue (no real image
# is built). NOT an authoritative digest.
syn_hex() { printf '%s' "$1" | sha256_hex_stdin; }

# A deterministic, non-placeholder full sha256:<64hex> OCI-shaped sample digest.
syn_oci() { printf 'sha256:%s' "$(syn_hex "$1")"; }

# Real BLAKE3 (bare 64-hex) of a file, for on-venue build-evidence hashing. Requires
# b3sum (a venue dependency); never invoked in the off-venue dry-run.
blake3_hex_file() {
  require_cmd b3sum
  b3sum "$1" | awk '{print $1}'
}

# True when the OFF-VENUE dry-run is requested (SUMCHAIN_B0PRE_DRYRUN=1). The dry
# run emits real-SHAPED sample files matching the exact production schema, WITHOUT
# Docker / toolchains, so the producer→consumer compatibility tests and the two
# demonstrations can run where no venue exists. Dry-run output is never authoritative.
is_dryrun() { [ "${SUMCHAIN_B0PRE_DRYRUN:-0}" = "1" ]; }
