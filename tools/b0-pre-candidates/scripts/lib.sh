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
  free="$(disk_free_gib "$path")"
  [ "${free:-0}" -ge "$min" ] || die "need >= ${min}GiB free at $path; only ${free:-0}GiB available"
}

# ---- Disk telemetry primitives ---------------------------------------------
# Free whole-GiB available on the filesystem holding PATH (0 if unknown).
disk_free_gib() {
  local path="$1" free
  free="$(df -Pg "$path" 2>/dev/null | awk 'NR==2{print $4}')" || free=0
  printf '%s' "${free:-0}"
}

# Disk used (whole MiB) by a directory tree; 0 if it does not exist.
dir_used_mib() {
  local path="$1"
  [ -e "$path" ] || { printf '0'; return; }
  du -sm "$path" 2>/dev/null | awk '{print $1}'
}

# Fail-closed BEFORE a stage runs if fewer than <min> GiB are free at <path>. Used to
# stop a stage whose estimated disk headroom is unavailable, rather than crashing part
# way through a large build/extraction.
require_headroom_gib() {
  local path="$1" min="$2" stage="${3:-next stage}" free
  free="$(disk_free_gib "$path")"
  [ "${free:-0}" -ge "$min" ] \
    || die "insufficient disk headroom for ${stage}: need >= ${min}GiB free at $path, have ${free:-0}GiB"
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

# ---- Authoritative container build context (curated, minimal, reproduced layout) ---
#
# The official guest dep graph is
#   candidates/<cand>/guest  --(path ../../../guest-core)-->  guest-core
#   guest-core               --(path ../../../crates/sumchain-wire)-->  sumchain-wire
# and `sumchain-wire` is a WORKSPACE MEMBER that inherits `.workspace = true` keys from
# the repo-root `Cargo.toml`. Copying only `candidates/<cand>` into the image (the old
# behaviour) leaves those two crates + the workspace root absent, so the path deps and
# the `.workspace` inheritance cannot resolve in-container. `stage_container_context`
# reproduces the EXACT repo-relative layout of ONLY that graph into a curated staging
# dir used as the Docker build context — no unrelated production crate is copied
# (isolation). The reproduced repo root maps to `/work` in the image, so:
INCONTAINER_ROOT="/work"

# The in-container candidate workspace dir (its `[workspace]` root). The path deps
# resolve because guest-core sits at /work/tools/b0-pre-candidates/guest-core and
# sumchain-wire at /work/crates/sumchain-wire, exactly as in the source tree.
incontainer_candidate_dir() { printf '%s/tools/b0-pre-candidates/candidates/%s' "$INCONTAINER_ROOT" "$1"; }

# The real repo root (two levels above tools/b0-pre-candidates). ROOT is set by every
# script that sources this lib to tools/b0-pre-candidates.
repo_root() { (cd "$ROOT/../.." && pwd); }

# Write the CURATED, MINIMAL workspace-root manifest for the staged context. It carries
# EXACTLY the `[workspace.package]` keys + `[workspace.dependencies]` entries that
# `crates/sumchain-wire` inherits via `{ workspace = true }` / `.workspace = true`, plus
# ONLY sumchain-wire as a member, and excludes `tools` exactly as the real repo root
# does (so the staged guest-core + candidate workspace under tools/ stay standalone /
# self-rooted, never members). Values are copied verbatim from the real repo-root
# Cargo.toml; the structural staging test fails on any drift or missing inherited key.
write_curated_workspace_root() {
  local dest="$1"
  cat > "$dest" <<'TOML'
# CURATED, MINIMAL workspace root for the B0-PRE official-guest container context.
# GENERATED by scripts/stage_context.sh (see lib.sh: write_curated_workspace_root).
#
# It exists ONLY so the frozen wire leaf `crates/sumchain-wire` — a real workspace
# member that inherits `.workspace = true` keys — resolves those inherited values
# inside the ISOLATED build context, WITHOUT copying the production workspace or any
# unrelated crate. It contains EXACTLY the sections sumchain-wire inherits:
#   [workspace.package]     : edition, authors, license, repository
#   [workspace.dependencies]: the deps its [dependencies]/[dev-dependencies] pull with
#                             `{ workspace = true }`
# and ONLY sumchain-wire as a member. `tools` is excluded exactly as in the real repo
# root, so the staged guest-core + candidate workspace (under tools/) stay standalone /
# self-rooted just like in-tree. Values are verbatim from the real repo-root Cargo.toml;
# any drift is caught by the structural staging test
# (tools/b0-pre-validator/tests/container_context_staging.rs).
[workspace]
resolver = "2"
members = ["crates/sumchain-wire"]
exclude = ["tools"]

[workspace.package]
edition = "2021"
authors = ["SUM Chain Team"]
license = "MIT OR Apache-2.0"
repository = "https://github.com/SUM-INNOVATION/sum-chain"

[workspace.dependencies]
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
serde-big-array = "0.5"
bincode = "1.3"
hex = "0.4"
bs58 = "0.5"
blake3 = "1.5"
thiserror = "1.0"
sha2 = "0.10"
TOML
}

# Copy a source tree into the staged context, then prune build scratch (target/) and
# ANY Cargo.lock (host locks are refused; the authoritative lock is generated
# in-container). Portable across GNU and BSD userland.
stage_copy_tree() {
  local src="$1" dst="$2"
  [ -d "$src" ] || die "stage_copy_tree: source '$src' is not a directory"
  mkdir -p "$(dirname "$dst")"
  cp -R "$src" "$dst"
  find "$dst" -type d -name target -prune -exec rm -rf {} + 2>/dev/null || true
  find "$dst" -type f -name Cargo.lock -delete 2>/dev/null || true
}

# Stage the curated, minimal, reproduced-layout Docker build context for one candidate
# into $stage. Reproduces ONLY the official guest dep graph at its exact repo-relative
# paths so the path deps + `.workspace` inheritance resolve in-container, and NOTHING
# else from the production workspace. Deterministic + off-venue safe (no Docker/toolchain).
stage_container_context() {
  local candidate="$1" stage="$2"
  case "$candidate" in sp1|risc0) ;; *) die "stage_container_context: candidate must be sp1|risc0 (got '${candidate:-}')" ;; esac
  [ -n "$stage" ] || die "stage_container_context: staging dir argument required"
  local repo; repo="$(repo_root)"

  rm -rf "$stage"
  mkdir -p "$stage"
  # 1) the frozen wire leaf (workspace member; path-dep target of guest-core).
  stage_copy_tree "$repo/crates/sumchain-wire" "$stage/crates/sumchain-wire"
  # 2) the candidate-neutral shared guest core (path-dep target of the candidate guest).
  stage_copy_tree "$ROOT/guest-core" "$stage/tools/b0-pre-candidates/guest-core"
  # 3) ONLY this candidate's workspace (host + guest); the other candidate never enters.
  stage_copy_tree "$ROOT/candidates/$candidate" "$stage/tools/b0-pre-candidates/candidates/$candidate"
  # 4) the frozen guest fixtures at the reproduced repo-relative path the guest-core
  #    sources reference (`../../../../docs/b0-pre/...` from guest-core/tests + the
  #    emit_official_guest_input example the venue runs).
  mkdir -p "$stage/docs/b0-pre/fixtures/workload" "$stage/docs/b0-pre/exp"
  cp "$repo/docs/b0-pre/fixtures/workload/official.json" "$stage/docs/b0-pre/fixtures/workload/official.json"
  cp "$repo/docs/b0-pre/exp/exp_table_q16.json"          "$stage/docs/b0-pre/exp/exp_table_q16.json"
  cp "$repo/docs/b0-pre/exp/exp_table_q16.json.hash"     "$stage/docs/b0-pre/exp/exp_table_q16.json.hash"
  # 5) the curated minimal workspace root (sumchain-wire inheritance only).
  write_curated_workspace_root "$stage/Cargo.toml"
  # Belt-and-suspenders: no Cargo.lock may exist anywhere in the staged context (the
  # authoritative lock is generated in-container and bound; a host lock is refused).
  find "$stage" -type f -name Cargo.lock -delete 2>/dev/null || true
}

# A deterministic BLAKE3 identity over the exact bytes of a staged context: BLAKE3 of
# the sorted list of "<relpath> <blake3(file)>" lines. Bound into the #154 build
# evidence (via the builder command log) so the staged guest-source/context identity is
# recorded without changing any evidence schema. Requires b3sum (a venue dependency).
staged_context_blake3() {
  local stage="$1"
  require_cmd b3sum
  ( cd "$stage" && find . -type f | LC_ALL=C sort | while IFS= read -r f; do
      printf '%s %s\n' "$f" "$(b3sum "$f" | awk '{print $1}')"
    done ) | b3sum | awk '{print $1}'
}
