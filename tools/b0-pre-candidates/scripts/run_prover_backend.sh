#!/usr/bin/env bash
# Host-side restricted runner for a Groth16 prover OCI backend (sp1-gnark / risc0-groth16).
#
# The terminal Groth16 backend is run BY THE TRUSTED HOST ORCHESTRATOR — never from inside a
# candidate container, and never with the Docker socket mounted into a candidate. This wrapper
# is the single choke point that enforces the sandbox and FAILS CLOSED if any restriction
# cannot be applied:
#   * the image is referenced BY IMMUTABLE DIGEST and pulled never (--pull never);
#   * the loaded image identity is RECONCILED to the pinned config digest before running;
#   * --network none, --read-only rootfs, --cap-drop ALL, --security-opt no-new-privileges;
#   * circuit + input are bind-mounted READ-ONLY; the ONE writable mount is an isolated,
#     single-use per-proof output dir; a writable tmpfs /tmp is provided for scratch;
#   * NO docker socket, NO --privileged, NO --cap-add, NO host networking.
#
# Usage:
#   run_prover_backend.sh --image-digest <repo@sha256:..> --config-digest <sha256:..> \
#       --circuit-ro <dir> --input-ro <file> --output <dir> [--extra-ro name=<path>]... \
#       -- <container args...>
# Modes: default = reconcile + run; --print-argv = emit the exact docker argv (after digest
#   checks) WITHOUT running docker or reconciling (used by the off-venue contract test).
set -uo pipefail

die() { printf 'REFUSED: %s\n' "$*" >&2; exit 1; }
is_digest_ref() { printf '%s' "$1" | grep -Eq '@sha256:[0-9a-f]{64}$'; }
is_sha256_digest() { printf '%s' "$1" | grep -Eq '^sha256:[0-9a-f]{64}$'; }

IMAGE=""; CONFIG_DIGEST=""; CIRCUIT_RO=""; INPUT_RO=""; OUTPUT=""; PRINT_ARGV=0
declare -a EXTRA_RO=()
declare -a CARGS=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    --image-digest)  IMAGE="$2"; shift 2 ;;
    --config-digest) CONFIG_DIGEST="$2"; shift 2 ;;
    --circuit-ro)    CIRCUIT_RO="$2"; shift 2 ;;
    --input-ro)      INPUT_RO="$2"; shift 2 ;;
    --output)        OUTPUT="$2"; shift 2 ;;
    --extra-ro)      EXTRA_RO+=("$2"); shift 2 ;;
    --print-argv)    PRINT_ARGV=1; shift ;;
    --) shift; CARGS=("$@"); break ;;
    *) die "unknown argument: $1" ;;
  esac
done

# --- fail-closed precondition checks (apply in BOTH modes so the test covers them) ---
[ -n "$IMAGE" ] || die "--image-digest is required"
is_digest_ref "$IMAGE" || die "--image-digest must be an immutable <repo>@sha256:<64hex> reference (a mutable tag is refused): $IMAGE"
[ -n "$CONFIG_DIGEST" ] || die "--config-digest is required (the pinned image config identity)"
is_sha256_digest "$CONFIG_DIGEST" || die "--config-digest must be sha256:<64hex>: $CONFIG_DIGEST"
[ -n "$CIRCUIT_RO" ] || die "--circuit-ro is required"
[ -n "$OUTPUT" ] || die "--output is required (an isolated, single-use per-proof directory)"
# The output dir must be freshly empty (single-use), so a reused/dirty work dir is refused.
if [ -e "$OUTPUT" ]; then
  [ -d "$OUTPUT" ] || die "--output exists and is not a directory: $OUTPUT"
  if [ -n "$(ls -A "$OUTPUT" 2>/dev/null)" ]; then die "--output must be an EMPTY single-use dir (reused proof work dir refused): $OUTPUT"; fi
fi

# --- construct the restricted docker argv ---
build_argv() {
  local -a a=(docker run --rm
    --pull never
    --network none
    --read-only
    --cap-drop ALL
    --security-opt no-new-privileges
    --tmpfs /tmp:rw,nosuid,nodev,noexec,size=2g
    --mount "type=bind,source=$CIRCUIT_RO,target=/circuit,readonly"
    --mount "type=bind,source=$OUTPUT,target=/output"
  )
  if [ -n "$INPUT_RO" ]; then
    a+=(--mount "type=bind,source=$INPUT_RO,target=/input,readonly")
  fi
  if [ "${#EXTRA_RO[@]}" -gt 0 ]; then
    local e
    for e in "${EXTRA_RO[@]}"; do
      local name="${e%%=*}" path="${e#*=}"
      a+=(--mount "type=bind,source=$path,target=/$name,readonly")
    done
  fi
  a+=("$IMAGE")
  if [ "${#CARGS[@]}" -gt 0 ]; then
    a+=("${CARGS[@]}")
  fi
  printf '%s\0' "${a[@]}"
}

if [ "$PRINT_ARGV" -eq 1 ]; then
  # Emit the argv (NUL-delimited) for the off-venue contract test; do NOT run docker.
  build_argv
  exit 0
fi

command -v docker >/dev/null 2>&1 || die "docker is required for the host-side prover sandbox"
[ -d "$CIRCUIT_RO" ] || die "--circuit-ro is not a directory: $CIRCUIT_RO"
[ -z "$INPUT_RO" ] || [ -f "$INPUT_RO" ] || die "--input-ro is not a file: $INPUT_RO"
mkdir -p "$OUTPUT" || die "cannot create --output dir: $OUTPUT"

# Immutable image-identity reconciliation: the loaded image's config identity MUST equal the
# pinned config digest. containerd/classic stores report .Id differently, so we compare the
# manifest's resolved config against the pin via docker image inspect.
loaded="$(docker image inspect --format '{{.Id}}' "$IMAGE" 2>/dev/null)" \
  || die "image not present locally (pull-by-digest required beforehand; --pull never here): $IMAGE"
# .Id may be the config digest (classic) or the manifest/index digest (containerd). Accept only
# when it equals the pinned config digest OR the pinned image ref's digest resolves to it; we
# require an explicit config match to avoid conflating manifest/index with config.
cfg="$(docker image inspect --format '{{.Config.Image}}' "$IMAGE" 2>/dev/null)"
if [ "$loaded" != "$CONFIG_DIGEST" ]; then
  # Fall back to reading the image config digest via inspect metadata; refuse if we cannot prove
  # the loaded image's config equals the pin.
  got_cfg="$(docker inspect --format '{{index .RepoDigests 0}}' "$IMAGE" 2>/dev/null || true)"
  die "image identity reconciliation FAILED: loaded .Id=$loaded (cfg-image=$cfg repodigest=$got_cfg) does not equal pinned config $CONFIG_DIGEST; refusing to run an unreconciled prover image"
fi

# Run the restricted container.
mapfile -d '' ARGV < <(build_argv)
exec "${ARGV[@]}"
