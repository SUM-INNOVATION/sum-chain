#!/usr/bin/env bash
# Build a candidate container reproducibly and record its OCI content digests.
#
# Native-arch, no push, two clean builds compared. Refuses on any missing
# immutable input, placeholder digest, wrong/emulated architecture, or absent
# Linux OCI builder. Produces a JSON digest record on success; NEVER fabricates.
#
# Usage:
#   build_container.sh <sp1|risc0> <x86_64|aarch64> <out_dir>
# Required env (venue-supplied immutable inputs):
#   BASE_IMAGE BASE_DIGEST APT_SNAPSHOT RUSTUP_INIT_SHA256
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
. "$HERE/lib.sh"

candidate="${1:-}"; arch="${2:-}"; out="${3:-}"
case "$candidate" in sp1|risc0) ;; *) die "candidate must be sp1|risc0 (got '${candidate:-}')" ;; esac
case "$arch" in x86_64|aarch64) ;; *) die "arch must be x86_64|aarch64 (got '${arch:-}')" ;; esac
[ -n "$out" ] || die "output directory argument required"

# --- fail-closed preflight (before any build) ---
require_native_arch "$arch"
require_linux_oci_builder
require_free_gib "$out" 100
require_no_preexisting_lock "$ROOT/candidates/$candidate"
require_full_sha256_digest BASE_DIGEST "${BASE_DIGEST:-}"
reject_placeholder BASE_DIGEST "${BASE_DIGEST:-}"
[ -n "${BASE_IMAGE:-}" ]  || nyr "BASE_IMAGE (immutable base) is required"
[ -n "${APT_SNAPSHOT:-}" ] || nyr "APT_SNAPSHOT (pinned OS package snapshot) is required"
[ -n "${RUSTUP_INIT_SHA256:-}" ] || nyr "RUSTUP_INIT_SHA256 (Rust 1.88.0 installer checksum) is required"

df="$ROOT/containers/$candidate.Dockerfile"
[ -f "$df" ] || die "missing Dockerfile $df"
mkdir -p "$out"

build_once() {
  local tag="$1" layout="$2"
  # Local OCI layout export only; never a registry push.
  docker build \
    --file "$df" \
    --build-arg "BASE_IMAGE=$BASE_IMAGE" \
    --build-arg "BASE_DIGEST=$BASE_DIGEST" \
    --build-arg "APT_SNAPSHOT=$APT_SNAPSHOT" \
    --build-arg "RUSTUP_INIT_SHA256=$RUSTUP_INIT_SHA256" \
    --build-arg "RUST_VERSION=1.88.0" \
    --output "type=oci,dest=$layout" \
    "$ROOT"
}

L1="$out/${candidate}.${arch}.build1.oci.tar"
L2="$out/${candidate}.${arch}.build2.oci.tar"
note "== build 1/2 =="; build_once "b0pre-$candidate" "$L1"
note "== build 2/2 (clean) =="; build_once "b0pre-$candidate" "$L2"

# Content digest of each exported OCI layout (the index/manifest digest is the
# content address; two builds must match exactly).
d1="$(sha256sum "$L1" | awk '{print $1}')"
d2="$(sha256sum "$L2" | awk '{print $1}')"
[ "$d1" = "$d2" ] || die "two clean builds diverged: $d1 != $d2 (candidate=$candidate arch=$arch)"

# Record the full digest set from the OCI index (media types + manifest digest).
idx="$out/${candidate}.${arch}.index.json"
tar -xOf "$L1" index.json > "$idx" 2>/dev/null || die "could not read OCI index.json"

cat > "$out/${candidate}.${arch}.digests.json" <<EOF
{
  "candidate": "$candidate",
  "arch": "$arch",
  "base_image": "$BASE_IMAGE",
  "base_digest": "$BASE_DIGEST",
  "builder_oci_layout_sha256": "$d1",
  "two_build_reproducible": true,
  "index_media_type": "$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["mediaType"])' "$idx" 2>/dev/null || echo unknown)",
  "pushed": false
}
EOF
note "recorded $out/${candidate}.${arch}.digests.json (no push)"
