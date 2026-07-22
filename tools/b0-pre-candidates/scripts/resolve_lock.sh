#!/usr/bin/env bash
# Produce the in-container-generated candidate Cargo.lock for one candidate, copied
# out to the workdir as the Stage-6 lock input (<Candidate>.Cargo.lock), together
# with its generated-in-container PROVENANCE. The lock is the full transitive source
# of truth resolved by `cargo generate-lockfile` INSIDE the pinned builder image;
# the host never supplies it.
#
# Blocker 2 (host-lock rejection): the authoritative path REFUSES any host-supplied
# lock. The former SP1_CONTAINER_LOCK / RISC0_CONTAINER_LOCK host-path acceptance is
# GONE — setting either is an error. The lock is generated in-container, exported,
# bound to (candidate, arch, container_digest, source_commit, command_log), and its
# hash is recomputed from the EXPORTED bytes and independently re-verified by
# `venue-verify verify-lock` (which recomputes it again and rejects a host origin or
# any mismatch). Off-venue (no Docker/builder image) this fails closed.
#
# OFF-VENUE dry run (SUMCHAIN_B0PRE_DRYRUN=1) writes a real-SHAPED sample lock so the
# compatibility test can hash a lock without a container.
#
# Usage: resolve_lock.sh <sp1|risc0> <out_dir>
# Required env (authoritative): BUILDER_IMAGE_REF, BUILDER_IMAGE_DIGEST (sha256:...),
#                               SCHEMA_ARCH (X86_64|Aarch64).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
# shellcheck source=lib.sh
. "$HERE/lib.sh"

candidate="${1:-}"; out="${2:-}"
case "$candidate" in sp1|risc0) ;; *) die "candidate must be sp1|risc0 (got '${candidate:-}')" ;; esac
[ -n "$out" ] || die "output directory argument required"
mkdir -p "$out"
case "$candidate" in sp1) schema_cand=Sp1 ;; risc0) schema_cand=Risc0 ;; esac
dest="$out/$schema_cand.Cargo.lock"

if is_dryrun; then
  {
    printf '# TEST_ONLY synthetic %s Cargo.lock (dry-run sample; not a real lock)\n' "$schema_cand"
    printf 'version = 3\n'
  } > "$dest"
  note "wrote SYNTHETIC $dest"
  exit 0
fi

# AUTHORITATIVE: the lock is GENERATED in-container; a host-supplied lock is refused.
[ -z "${SP1_CONTAINER_LOCK:-}${RISC0_CONTAINER_LOCK:-}" ] \
  || die "host-supplied lock env (SP1_CONTAINER_LOCK/RISC0_CONTAINER_LOCK) is refused; the lock must be generated in-container"
require_linux_oci_builder
require_cmd b3sum
require_cmd python3
[ -n "${BUILDER_IMAGE_REF:-}" ] || nyr "BUILDER_IMAGE_REF (the pinned builder image the lock is generated inside) is required"
require_full_sha256_digest BUILDER_IMAGE_DIGEST "${BUILDER_IMAGE_DIGEST:-}"
reject_placeholder BUILDER_IMAGE_DIGEST "${BUILDER_IMAGE_DIGEST:-}"
arch="${SCHEMA_ARCH:-}"
case "$arch" in X86_64|Aarch64) ;; *) die "SCHEMA_ARCH must be X86_64|Aarch64 (got '${arch:-}')" ;; esac
require_no_preexisting_lock "$ROOT/candidates/$candidate"
[ -z "$(git -C "$ROOT" status --porcelain 2>/dev/null || echo dirty)" ] \
  || die "source tree is not clean; refuse to resolve from a dirty state"
source_commit="$(git -C "$ROOT" rev-parse HEAD)"

VAL="$ROOT/../b0-pre-validator/Cargo.toml"
[ -f "$VAL" ] || die "missing validator manifest $VAL"

# Generate the lock INSIDE the pinned builder image (no network beyond the pinned
# registry the image is configured for) and export the resulting bytes + the exact
# command log. The host filesystem contributes no lock.
gen_cmd="$out/$schema_cand.generate-lockfile.cmd"
gen_log="$out/$schema_cand.generate-lockfile.log"
printf 'docker run --rm --pull never %s cargo generate-lockfile (candidate=%s)\n' \
  "$BUILDER_IMAGE_DIGEST" "$candidate" > "$gen_cmd"
docker run --rm --pull never "$BUILDER_IMAGE_REF" \
  bash -c "cd /work/candidates/$candidate && cargo generate-lockfile && cat Cargo.lock" \
  > "$dest" 2> "$gen_log" \
  || die "in-container 'cargo generate-lockfile' failed for $candidate (no host lock is substituted)"
[ -s "$dest" ] || die "in-container lock export for $candidate is empty; refusing"

cmdlog_hex="$(blake3_hex_file "$gen_cmd")"
# Recompute the domain-separated lock hash from the EXPORTED bytes (never a claim).
lock_hex="$(cargo run --quiet --locked --manifest-path "$VAL" --bin venue-verify -- lock-hash "$dest")" \
  || die "lock-hash recomputation failed for $dest"

# Record the generated-in-container provenance bound to (candidate, arch,
# container_digest, source_commit, command_log, lock_hash).
prov="$out/$schema_cand.lock-provenance.json"
python3 - "$prov" "$schema_cand" "$arch" "$BUILDER_IMAGE_DIGEST" "$source_commit" "$cmdlog_hex" "$lock_hex" <<'PY'
import json, sys
path, cand, arch, digest, commit, cmdlog, lockhash = sys.argv[1:8]
with open(path, "w") as f:
    json.dump({
        "candidate": cand,
        "arch": arch,
        "origin": "generated-in-container",
        "container_digest": digest,
        "source_commit": commit,
        "command_log_blake3_hex": cmdlog,
        "lock_blake3_hex": lockhash,
    }, f, indent=2)
    f.write("\n")
PY

# Independently re-verify: reject a host origin and recompute the hash from the
# exported bytes again (defence in depth — the resolver's recorded hash is not trusted).
cargo run --quiet --locked --manifest-path "$VAL" --bin venue-verify -- \
  verify-lock "$prov" "$dest" \
  || die "lock provenance verification failed (host-originated lock or hash mismatch)"

note "recorded in-container $dest + provenance $prov"
