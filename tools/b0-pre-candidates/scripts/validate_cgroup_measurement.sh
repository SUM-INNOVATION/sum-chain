#!/usr/bin/env bash
# Standalone bounded venue preflight for the B0-FINAL proving-cgroup PEAK measurement.
#
# It runs a HARMLESS container from a LOCALLY-PRESENT, IMMUTABLE linux/amd64 image (operator-supplied;
# NEVER pulled) under the SAME full sandbox and the SAME driver-aware measurement lifecycle the
# firewall uses for real proofs — by SOURCING the firewall's actual helpers (read_cgroup_peak /
# make_fresh_cell_cgroup / detect_cgroup_driver / make_fresh_cell_slice / capture_container_cgroup /
# run_measured_backend), never a re-implementation. The container allocates ~64 MiB into its cgroup;
# this script then asserts a NONZERO memory.peak was captured from the container's OWN resolved cgroup
# and that the transient scope/cell was cleaned up.
#
# It NEVER invokes a prover, mounts a circuit/witness, reconciles a backend image, pulls, or emits any
# measurement evidence — it only proves the venue's Docker cgroup driver + delegation let the
# firewall's lifecycle capture a real peak. Run it on the x86 systemd-Docker venue BEFORE any
# measurement (and before Commit A). Exit 0 = the measurement mechanism works on this host.
#
# Required env:
#   B0PRE_REAL_DOCKER      absolute path to the real docker (default: `command -v docker`)
#   B0PRE_PROVING_CGROUP   the delegated proving parent (a *.slice under systemd)
#   B0PRE_CGROUP_ROOT      cgroup v2 root (default /sys/fs/cgroup)
#   B0PRE_VALIDATION_IMAGE REQUIRED. A locally-present, immutable linux/amd64 image. PREFER a
#                          digest-pinned ref (repo@sha256:<64hex>); a bare tag is accepted only when
#                          already present locally — its resolved immutable image Id is recorded, and
#                          NOTHING is ever pulled (pull-never). The image must provide POSIX `sh`+`dd`.
#   B0PRE_VALIDATION_EVIDENCE  optional path; a JSON evidence line is appended (always echoed to stdout)
set -uo pipefail

SCRIPTDIR="$(cd "$(dirname "$0")" && pwd)"
FW="$SCRIPTDIR/docker_firewall.sh"
[ -f "$FW" ] || { echo "REFUSED: firewall not found next to this script: $FW" >&2; exit 2; }
EMITTER="$SCRIPTDIR/emit_cgroup_evidence.py"
[ -f "$EMITTER" ] || { echo "REFUSED: evidence emitter not found next to this script: $EMITTER" >&2; exit 2; }

REAL_DOCKER="${B0PRE_REAL_DOCKER:-$(command -v docker 2>/dev/null || true)}"
[ -n "$REAL_DOCKER" ] && [ -x "$REAL_DOCKER" ] || { echo "REFUSED: real docker not executable: '${REAL_DOCKER:-<unset>}'" >&2; exit 2; }
PROVING_CGROUP="${B0PRE_PROVING_CGROUP:-}"
[ -n "$PROVING_CGROUP" ] || { echo "REFUSED: B0PRE_PROVING_CGROUP unset (the delegated proving parent)" >&2; exit 2; }
CGROUP_ROOT="${B0PRE_CGROUP_ROOT:-/sys/fs/cgroup}"
IMAGE="${B0PRE_VALIDATION_IMAGE:-}"
[ -n "$IMAGE" ] || { echo "REFUSED: B0PRE_VALIDATION_IMAGE unset — supply a locally-present, immutable linux/amd64 image (prefer a repo@sha256:<digest> ref); this script NEVER pulls." >&2; exit 2; }
EVIDENCE="${B0PRE_VALIDATION_EVIDENCE:-}"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

# Collaborators the extracted helpers call (real, not stubbed).
refuse() { echo "VALIDATION-REFUSED: $*" >&2; exit 1; }
run_real() { env -i PATH=/usr/bin:/bin HOME="${HOME:-/root}" "$REAL_DOCKER" "$@"; }

# Source the firewall's REAL measurement helpers (read_cgroup_peak .. run_measured_backend). Sourcing
# the shipped code — not a copy — is what makes this a faithful preflight of the firewall lifecycle.
awk '/^read_cgroup_peak\(\)/{f=1} /^# --- recursion guard/{f=0} f' "$FW" > "$TMP/fns.sh"
grep -q '^run_measured_backend()' "$TMP/fns.sh" || { echo "REFUSED: could not source firewall measurement helpers" >&2; exit 2; }
# shellcheck disable=SC1090
. "$TMP/fns.sh"

# Preconditions the real proving path also requires (surface them here with actionable messages).
[ -f "$CGROUP_ROOT/cgroup.controllers" ] || refuse "not cgroup v2 at $CGROUP_ROOT"
[ -d "$CGROUP_ROOT/$PROVING_CGROUP" ] || refuse "delegated proving parent absent: $CGROUP_ROOT/$PROVING_CGROUP"

# IMMUTABLE, PRESENT, linux/amd64, pull-never. `image inspect` reads the LOCAL store only (never a
# network pull); a missing image fails closed here rather than being fetched. Resolve + record the
# immutable content address (image Id) and platform so the validated image is pinned in evidence.
IMG_JSON="$(run_real image inspect "$IMAGE" 2>/dev/null)" || refuse "validation image NOT present locally (this script never pulls): $IMAGE"
IMG_ID="$(run_real image inspect "$IMAGE" --format '{{.Id}}' 2>/dev/null)"
IMG_OS="$(run_real image inspect "$IMAGE" --format '{{.Os}}' 2>/dev/null)"
IMG_ARCH="$(run_real image inspect "$IMAGE" --format '{{.Architecture}}' 2>/dev/null)"
IMG_REPODIGESTS="$(run_real image inspect "$IMAGE" --format '{{join .RepoDigests ","}}' 2>/dev/null)"
[ "$IMG_OS/$IMG_ARCH" = "linux/amd64" ] || refuse "validation image is not linux/amd64 (got '${IMG_OS:-?}/${IMG_ARCH:-?}'): $IMAGE"
printf '%s' "$IMG_ID" | grep -Eq '^sha256:[0-9a-f]{64}$' || refuse "could not resolve an immutable image Id for $IMAGE"
case "$IMAGE" in
  *@sha256:*) IMG_IMMUTABLE=digest-ref ;;
  *) IMG_IMMUTABLE="tag-ref(local, Id-pinned)"; echo "NOTE: $IMAGE is a mutable tag; validating the LOCAL image $IMG_ID with pull-never. A repo@sha256 ref is preferred." >&2 ;;
esac

driver="$(detect_cgroup_driver)" || refuse "could not detect the Docker cgroup driver"
echo "cgroup driver: $driver"
echo "validation image: ref=$IMAGE id=$IMG_ID platform=$IMG_OS/$IMG_ARCH repo_digests=[${IMG_REPODIGESTS}] immutability=$IMG_IMMUTABLE pull=never"

# Harmless workload under the FULL sandbox: allocate ~64 MiB into the container's own cgroup by
# writing to its in-memory /tmp (holding it), so a correctly-isolated peak is well above zero. It
# then HOLDS the allocation briefly so the firewall's live PID inspection + per-cell-slice monitoring
# have a window (real provers run for minutes; this harmless probe would otherwise exit too fast).
ALLOC_MIB=64
HOLD_S="${B0PRE_VALIDATION_HOLD_S:-4}"
WORKLOAD="dd if=/dev/zero of=/tmp/blob bs=1M count=${ALLOC_MIB} 2>/dev/null; sync; cat /tmp/blob >/dev/null; sleep ${HOLD_S}"
CONTAINER_CMD="sh -c \"$WORKLOAD\""
declare -a BASE=(--pull never --network none --read-only
  --cap-drop ALL --security-opt no-new-privileges
  --tmpfs /tmp:rw,nosuid,nodev,size=256m
  "$IMAGE" sh -c "$WORKLOAD")
RUN_CMD="docker run --rm ${BASE[*]}"

echo "running harmless measured container (allocates ${ALLOC_MIB} MiB)…"
run_measured_backend 1 -- "${BASE[@]}"

# Classify the outcome. The workload status + peak are ALWAYS recorded in evidence — even on a
# teardown failure the measurement path itself succeeded, so its status must not be discarded.
result=pass; detail=""
MIN=$(( (ALLOC_MIB / 2) * 1024 * 1024 ))
if ! { [ -n "$MB_PEAK" ] && [ "$MB_PEAK" -gt 0 ] 2>/dev/null; }; then
  result=fail; detail="no nonzero peak captured (MB_PEAK='${MB_PEAK:-}')"
elif [ "$MB_PEAK" -lt "$MIN" ] 2>/dev/null; then
  result=fail; detail="captured peak ${MB_PEAK}B implausibly low (< ${MIN}B) — resolved cgroup likely not the container's own per-cell slice"
elif [ "$MB_STATUS" != 0 ]; then
  result=fail; detail="harmless container exited nonzero ($MB_STATUS)"
elif [ "${MB_CLEANUP_OK:-1}" != 1 ]; then
  result=cleanup_fail; detail="${MB_CLEANUP_DETAIL:-cleanup failed}"
fi

echo "resolved cgroup identity: $MB_CGID"
echo "captured memory.peak: ${MB_PEAK:-} bytes"
echo "workload exit status: ${MB_STATUS:-}"
[ "$result" = pass ] || echo "cgroup validation issue ($result): $detail" >&2

# Record evidence ALWAYS (the workload status is retained regardless of a cleanup outcome), through a
# fail-closed JSON encoder that correctly escapes every field and preserves types. On encoder failure
# nothing is written and the run fails closed. The already-validated docker_firewall.sh is untouched —
# this fix is entirely in the validation surface.
ev_line="$(python3 "$EMITTER" "${EVIDENCE:-}" \
  "$result" "$detail" "$driver" "$IMAGE" "$IMG_ID" "$IMG_OS" "$IMG_ARCH" "$IMG_REPODIGESTS" "$IMG_IMMUTABLE" \
  "$CONTAINER_CMD" "$RUN_CMD" "$MB_CGID" "${MB_PEAK:-}" "${MB_STATUS:-}" "${MB_CLEANUP_OK:-1}" \
  "${MB_TEARDOWN_ARGV:-}" "${MB_TEARDOWN_RC:-}" "${MB_TEARDOWN_STDERR:-}")" \
  || refuse "evidence JSON encoding failed (fail-closed; no evidence line emitted)"
[ -n "$EVIDENCE" ] && echo "evidence appended: $EVIDENCE"
[ -n "$ev_line" ] || refuse "evidence encoder produced no line (fail-closed)"

[ "$result" = pass ] || refuse "$result: $detail"
echo "PASS: the firewall cgroup-measurement lifecycle captured a nonzero, plausible per-cell-slice peak under the '$driver' driver (image $IMG_ID, pull-never), stopped the authenticated per-cell unit, and cleaned up."
exit 0
