#!/usr/bin/env bash
# B0-PRE Docker invocation FIREWALL — a tightly-scoped, additive trust mechanism (NOT a general
# docker shim). It is installed as an executable named `docker` on a dedicated dir that is
# prepended to PATH ONLY for the pinned SP1 6.3.1 / RISC Zero 3.0.5 proving subprocess, and removed
# immediately after. It exists because those SDKs invoke `docker run` for their Groth16 backend
# THEMSELVES, with permissive flags this firewall cannot otherwise control (writable mounts, default
# network, no dropped caps, and — RISC Zero — a hardcoded mutable tag). The firewall is the trusted
# host orchestrator: it intercepts ONLY the two exact backend `docker run` grammars, replaces the
# SDK image with the immutable digest, reconciles OCI identity against the v4 pin, injects the full
# sandbox, makes inputs read-only + outputs isolated-writable, hashes inputs before/after, sanitizes
# the child environment, records an execution attestation, and REFUSES everything else.
#
# Required env (set by the producer; all mandatory):
#   B0PRE_REAL_DOCKER      absolute, pre-verified path to the REAL docker binary (never resolved via PATH)
#   B0PRE_FIREWALL_ATTEST  path to append the JSON execution attestation to
#   B0PRE_PROOF_DIR        the fresh per-proof root; the ONLY writable-output root permitted
#   B0PRE_CONTENT_STORE    the digest-addressed content-store root (the SP1 circuit lives here, read-only)
set -uo pipefail

refuse() { echo "FIREWALL-REFUSED: $*" >&2; exit 97; }
sha() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" 2>/dev/null | awk '{print $1}'; else shasum -a 256 "$1" 2>/dev/null | awk '{print $1}'; fi; }
nlink() { stat -c '%h' "$1" 2>/dev/null || stat -f '%l' "$1" 2>/dev/null; }
# owner:group:octal-mode of a path (portable) — recorded in the attestation so it is auditable that
# world-accessible modes are limited to fresh ephemeral copies/outputs, never canonical inputs.
perms() { local p; p="$(stat -c '%U:%G:%a' "$1" 2>/dev/null || stat -f '%Su:%Sg:%Lp' "$1" 2>/dev/null)"; printf '%s=%s' "$(basename "$1")" "$p"; }

REAL_DOCKER="${B0PRE_REAL_DOCKER:-}"; [ -n "$REAL_DOCKER" ] || refuse "B0PRE_REAL_DOCKER unset"
ATTEST="${B0PRE_FIREWALL_ATTEST:-}";  [ -n "$ATTEST" ] || refuse "B0PRE_FIREWALL_ATTEST unset"
PROOF_DIR="${B0PRE_PROOF_DIR:-}";     [ -n "$PROOF_DIR" ] || refuse "B0PRE_PROOF_DIR unset"
CONTENT_STORE="${B0PRE_CONTENT_STORE:-}"

# B0-FINAL MEASUREMENT extension (ADDITIVE; unset in R5 / prove_fixture.sh, so behaviour
# there is byte-identical). When B0PRE_PROVING_CGROUP is set to a dedicated, delegated,
# freshly-reset cgroup path (relative to B0PRE_CGROUP_ROOT, default /sys/fs/cgroup), the
# PROVE backend container is placed in it via --cgroup-parent and its PEAK memory is read
# from that cgroup afterwards — the correct proving-RSS source (getrusage on the runner
# would miss the container). The measurement runner reads these attestation fields and
# FAILS CLOSED if they are absent, so a proving RSS is never silently unmeasured.
PROVING_CGROUP="${B0PRE_PROVING_CGROUP:-}"
CGROUP_ROOT="${B0PRE_CGROUP_ROOT:-/sys/fs/cgroup}"
read_cgroup_peak() { # <abs cgroup dir> -> prints peak bytes, or non-zero if unavailable
  local d="$1"; [ -n "$d" ] || return 1
  if [ -f "$d/memory.peak" ]; then cat "$d/memory.peak" 2>/dev/null
  elif [ -f "$d/memory.max_usage_in_bytes" ]; then cat "$d/memory.max_usage_in_bytes" 2>/dev/null
  else return 1; fi
}
# Create a FRESH, EXCLUSIVE, per-cell child cgroup under the delegated proving parent so the
# prove container's peak memory is isolated (never a shared/cumulative parent). Verifies the
# parent + child are cgroup-v2, the child is brand new (unique path) and EMPTY (no unrelated
# processes), and a peak file exists. Prints "<relative-for-cgroup-parent>\t<abs>". Fail closed.
make_fresh_cell_cgroup() {
  [ -n "$PROVING_CGROUP" ] || { echo "REFUSED: B0PRE_PROVING_CGROUP unset for measurement" >&2; return 1; }
  [ -f "$CGROUP_ROOT/cgroup.controllers" ] || { echo "REFUSED: not cgroup v2 at $CGROUP_ROOT" >&2; return 1; }
  local parent="$CGROUP_ROOT/$PROVING_CGROUP"
  [ -d "$parent" ] || { echo "REFUSED: delegated proving parent cgroup absent: $parent" >&2; return 1; }
  local rel="$PROVING_CGROUP/cell-$$-$RANDOM$RANDOM"
  local abs="$CGROUP_ROOT/$rel"
  [ ! -e "$abs" ] || { echo "REFUSED: cell cgroup path already exists (not fresh): $abs" >&2; return 1; }
  mkdir "$abs" 2>/dev/null || { echo "REFUSED: cannot create fresh cell cgroup $abs (delegation/permissions)" >&2; return 1; }
  # Exclusivity: a fresh cgroup must contain NO processes.
  if [ -s "$abs/cgroup.procs" ]; then echo "REFUSED: fresh cell cgroup is not empty: $abs" >&2; rmdir "$abs" 2>/dev/null; return 1; fi
  [ -e "$abs/memory.peak" ] || [ -e "$abs/memory.max_usage_in_bytes" ] || { echo "REFUSED: cell cgroup exposes no peak-memory file: $abs" >&2; rmdir "$abs" 2>/dev/null; return 1; }
  printf '%s\t%s' "$rel" "$abs"
}

# --- recursion guard: real docker must be an ABSOLUTE, executable path that is NOT this firewall ---
case "$REAL_DOCKER" in /*) ;; *) refuse "B0PRE_REAL_DOCKER must be absolute: $REAL_DOCKER" ;; esac
[ -x "$REAL_DOCKER" ] || refuse "real docker not executable: $REAL_DOCKER"
self="$(readlink -f "$0" 2>/dev/null || echo "$0")"
rd="$(readlink -f "$REAL_DOCKER" 2>/dev/null || echo "$REAL_DOCKER")"
[ "$rd" != "$self" ] || refuse "recursion guard: real docker resolves to the firewall itself"

# Diagnostic: log EVERY docker invocation the SDK routes through the firewall.
[ -n "${B0PRE_DIAG:-}" ] && { mkdir -p "$B0PRE_DIAG" 2>/dev/null; printf 'CALL: %s\n' "$*" >> "$B0PRE_DIAG/calls.log" 2>/dev/null; } || true

# --- frozen v4 backend identities (MUST match pin_contract.rs EXPECTED_OCI_BACKENDS) ---
SP1_REPO="ghcr.io/succinctlabs/sp1-gnark"
SP1_MANIFEST="sha256:be8555f1ad90870acd8c6ec7fd3ba0b1a2133ea9cddf25e130665aa651129e54"
SP1_CONFIG="sha256:ceb60d80f46cd8e5869abd778f26dc34c4f3bab205f3d1d5275e532121cced4e"
R0_REPO="risczero/risc0-groth16-prover"
R0_MANIFEST="sha256:7f173963196570b7a71816ed70565a4579264c5d2e3e0ecb028102538ad0e331"
R0_CONFIG="sha256:f6f756b0899c29d869d6a01fbbded3887a8f51429653177ee4b3ffad294324cd"
# The exact mutable references the SDKs emit (recognized ONLY to be replaced by the digest above).
SP1_SDK_IMAGE_RE='^(ghcr\.io/succinctlabs/sp1-gnark:.*|.*@sha256:[0-9a-f]{64})$'
R0_SDK_IMAGE='risczero/risc0-groth16-prover:v2025-04-03.1'

run_real() {  # exec real docker with a SANITIZED environment (strip DOCKER_HOST etc.)
  env -i PATH=/usr/bin:/bin HOME="${HOME:-/root}" "$REAL_DOCKER" "$@"
}

# Retry a real-docker READ (image/manifest inspect). `docker manifest inspect` is a REGISTRY
# query (network) that ghcr.io occasionally rate-limits / transiently fails; a genuine miss still
# fails closed after the attempts. Prints stdout on the first success; returns non-zero if all
# attempts fail. Usage: retry_real <attempts> <sleep_s> -- <docker args...>
retry_real() {
  local n="$1" s="$2"; shift 2; [ "${1:-}" = "--" ] && shift
  local i=1 out
  while :; do
    if out="$(run_real "$@" 2>/dev/null)"; then printf '%s' "$out"; return 0; fi
    [ "$i" -ge "$n" ] && return 1
    i=$((i + 1)); sleep "$s"
  done
}

# --- benign read-only probes the SDKs make before proving (assert_docker / is_docker_installed) ---
sub="${1:-}"
case "$sub" in
  --version|version) run_real "$@"; exit $? ;;
  info)              run_real info >/dev/null; exit $? ;;
  run) ;;  # intercepted below
  *) refuse "subcommand not permitted in the proving scope: '${sub}' (only run|info|--version)" ;;
esac

# ---- parse `docker run ...` against the two exact grammars -----------------------------------
shift  # drop 'run'
declare -a MOUNTS=()      # each "src:dest"
IMAGE=""; declare -a CARGS=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    --rm) shift ;;
    -v) [ "$#" -ge 2 ] || refuse "dangling -v"; MOUNTS+=("$2"); shift 2 ;;
    -v*) MOUNTS+=("${1#-v}"); shift ;;
    # Any other flag before the image is UNEXPECTED for these two grammars -> refuse (covers
    # --privileged, --cap-add, --device, --network, -e, --entrypoint, --mount, -p, extra -v, etc.)
    -*) refuse "unexpected docker flag in SDK argv (grammar violation): $1" ;;
    *) IMAGE="$1"; shift; CARGS=("$@"); break ;;
  esac
done
[ -n "$IMAGE" ] || refuse "no image in docker run argv"
INTERCEPTED_ARGV="run --rm $(printf -- '-v %s ' "${MOUNTS[@]:-}")$IMAGE ${CARGS[*]:-}"

# A path is safe iff it is absolute, real, contains no symlink escaping its root, and lies under an
# allowed root. Returns the canonical path.
under_root() { # <path> <root...>
  local p canon; p="$1"; shift
  canon="$(readlink -f "$p" 2>/dev/null || echo "")"
  [ -n "$canon" ] || return 1
  local r
  for r in "$@"; do
    local rc; rc="$(readlink -f "$r" 2>/dev/null || echo "$r")"
    case "$canon/" in "$rc"/*) printf '%s' "$canon"; return 0 ;; esac
  done
  return 1
}

# OCI reconciliation: the digest ref must resolve locally (pull-never), its amd64 platform manifest
# must equal the pin, and the manifest's config digest must equal the pinned config. Records the
# loaded image id. Refuses on any mismatch. Prints "manifest<TAB>config<TAB>loadedid".
reconcile_oci() { # <repo> <manifest_digest> <config_digest>
  local repo="$1" man="$2" cfg="$3" ref="$1@$2"
  [ "$(uname -m)" = "x86_64" ] || refuse "backend reconciliation: not native x86_64"
  # Local presence (content-addressed by manifest digest) — retried against transient hiccups.
  retry_real 5 2 -- image inspect "$ref" >/dev/null 2>&1 || refuse "pinned backend image not present locally (pull-never): $ref"
  # Config digest from the platform manifest. This is a network registry query; retry it so a
  # transient ghcr.io rate-limit does NOT silently drop reconciliation (which would otherwise let
  # an unreconciled backend run). A genuine failure still fails closed after the retries.
  local mjson gotcfg
  mjson="$(retry_real 5 2 -- manifest inspect "$ref")" || refuse "cannot inspect pinned manifest after retries (registry unreachable?): $ref"
  gotcfg="$(printf '%s' "$mjson" | grep -oE '"digest": *"sha256:[0-9a-f]{64}"' | head -1 | grep -oE 'sha256:[0-9a-f]{64}')"
  [ "$gotcfg" = "$cfg" ] || refuse "config digest mismatch for $ref (got ${gotcfg:-none}, pin $cfg)"
  local loaded; loaded="$(run_real image inspect "$ref" --format '{{.Id}}' 2>/dev/null)"
  [ -n "$loaded" ] || refuse "could not read loaded image id for $ref"
  printf '%s\t%s\t%s' "$man" "$cfg" "$loaded"
}

now_attest() { # append the JSON attestation record
  local cand="$1" rewritten="$2" recon="$3" mountmap="$4" prehash="$5" posthash="$6" outhash="$7" status="$8" permmap="${9:-}" peak="${10:-}" cgid="${11:-}"
  local ddg dver
  dver="$(run_real --version 2>/dev/null | head -1)"
  ddg="$(sha "$rd")"
  python3 - "$ATTEST" "$cand" "$INTERCEPTED_ARGV" "$rewritten" "$ddg" "$dver" "$recon" "$mountmap" "$prehash" "$posthash" "$outhash" "$status" "$permmap" "$peak" "$cgid" <<'PY'
import json,sys
p=sys.argv[1]
rec={"kind":"b0pre-docker-firewall-exec/v1","candidate":sys.argv[2],
 "intercepted_argv":sys.argv[3],"rewritten_argv":sys.argv[4],
 "real_docker_sha256":sys.argv[5],"real_docker_version":sys.argv[6],
 "oci_reconciliation":sys.argv[7],"mount_map":sys.argv[8],
 "input_hashes_pre":sys.argv[9],"input_hashes_post":sys.argv[10],
 "output_hashes":sys.argv[11],"exit_status":int(sys.argv[12]),
 "ephemeral_perms":sys.argv[13]}
# ADDITIVE B0-FINAL measurement fields: only present when the PROVE backend ran in a
# dedicated cgroup whose peak memory was measured (empty in R5 / verify, absent from JSON).
peak, cgid = sys.argv[14], sys.argv[15]
if peak and cgid:
    rec["proving_container_peak_rss_bytes"]=int(peak)
    rec["proving_cgroup_identity"]=cgid
open(p,"a").write(json.dumps(rec)+"\n")
PY
}

# Strict validator for the SP1 gnark VERIFY argv (the SDK verifies the proof it just produced):
#   verify --system groth16 --data-dir /circuit --proof-path /proof --vkey-hash <N>
#     --committed-values-digest <N> --exit-code <N> --proof-nonce <N> --vk-root <N> --output-path /output
validate_sp1_verify_argv() {
  [ "$#" = 19 ] || refuse "SP1 verify argv has $# fields, expected 19"
  [ "$1" = verify ] && [ "$2" = --system ] && [ "$3" = groth16 ] || refuse "SP1 verify: bad head"
  [ "$4" = --data-dir ] && [ "$5" = /circuit ] || refuse "SP1 verify: bad --data-dir"
  [ "$6" = --proof-path ] && [ "$7" = /proof ] || refuse "SP1 verify: bad --proof-path"
  [ "$8" = --vkey-hash ] && printf '%s' "$9" | grep -Eq '^[0-9]+$' || refuse "SP1 verify: bad --vkey-hash"
  [ "${10}" = --committed-values-digest ] && printf '%s' "${11}" | grep -Eq '^[0-9]+$' || refuse "SP1 verify: bad --committed-values-digest"
  [ "${12}" = --exit-code ] && printf '%s' "${13}" | grep -Eq '^[0-9]+$' || refuse "SP1 verify: bad --exit-code"
  [ "${14}" = --proof-nonce ] && printf '%s' "${15}" | grep -Eq '^[0-9]+$' || refuse "SP1 verify: bad --proof-nonce"
  [ "${16}" = --vk-root ] && printf '%s' "${17}" | grep -Eq '^[0-9]+$' || refuse "SP1 verify: bad --vk-root"
  [ "${18}" = --output-path ] && [ "${19}" = /output ] || refuse "SP1 verify: bad --output-path"
}

# Shared SP1 gnark backend run (prove OR verify). Both mount the read-only circuit (content store),
# ONE writable working input (the gnark backend opens it O_RDWR — witness for prove, proof for
# verify — so the CANONICAL stays UNMOUNTED+immutable and gnark gets an isolated writable COPY),
# and one isolated writable output. Full sandbox; OCI reconciliation; hash before/after; attest.
#   sp1_backend <label> <circuit_src> <inp_src> <inp_target> <out_src> -- <container-args...>
sp1_backend() {
  local label="$1" circuit_src="$2" inp_src="$3" inp_target="$4" out_src="$5"; shift 5
  [ "$1" = "--" ] && shift
  local -a cargs=("$@")
  local c_canon o_canon
  c_canon="$(under_root "$circuit_src" "$CONTENT_STORE")" || refuse "SP1 circuit mount not under content store: $circuit_src"
  o_canon="$(under_root "$out_src" "$PROOF_DIR")"         || refuse "SP1 output mount not under per-proof root: $out_src"
  [ ! -L "$inp_src" ] || refuse "SP1 $inp_target input is a symlink (refused): $inp_src"
  local inp_canon; inp_canon="$(under_root "$inp_src" "$PROOF_DIR")" || refuse "SP1 $inp_target input not under per-proof root: $inp_src"
  [ -f "$inp_canon" ] || refuse "SP1 $inp_target input is not a regular file: $inp_canon"
  [ "$(nlink "$inp_canon")" = 1 ] || refuse "SP1 $inp_target input has extra hard links: $inp_canon"
  local canon_h; canon_h="$(sha "$inp_canon")"
  local copy="$PROOF_DIR/fw-$label-copy.$$.$RANDOM.work"
  [ ! -e "$copy" ] || refuse "$label working-copy destination pre-exists (reused workspace): $copy"
  cp -- "$inp_canon" "$copy" || refuse "failed to create $label working-copy"
  [ ! -L "$copy" ] && [ -f "$copy" ] || refuse "$label working-copy is not a fresh regular file"
  local copy_pre; copy_pre="$(sha "$copy")"
  [ "$copy_pre" = "$canon_h" ] || { rm -f "$copy"; refuse "$label working-copy pre-hash != canonical hash"; }
  chmod 0666 "$copy" "$o_canon" || { rm -f "$copy"; refuse "cannot set $label copy/output mode"; }
  # reconcile_oci runs in this command substitution; its refuse() exits the SUBSHELL, so the exit
  # status MUST be propagated here (|| refuse) or an unreconciled backend would run with empty recon.
  local recon
  recon="$(reconcile_oci "$SP1_REPO" "$SP1_MANIFEST" "$SP1_CONFIG")" || { rm -f "$copy"; refuse "SP1 $label backend OCI reconciliation FAILED (see reason above); refusing to run an unreconciled backend"; }
  [ -n "$recon" ] || { rm -f "$copy"; refuse "SP1 $label backend OCI reconciliation returned no result"; }
  local ref="$SP1_REPO@$SP1_MANIFEST"
  local mmap="/circuit(ro)=$c_canon $inp_target(rw-COPY,canonical-unmounted)=$copy<-$inp_canon /output(rw)=$o_canon"
  # B0-FINAL measurement: place the PROVE (witness) container in a FRESH, EXCLUSIVE per-cell
  # cgroup so its PEAK memory is isolated; verify (proof) is left unchanged. No-op when unset (R5).
  local -a cgroup_args=(); local mpeak="" mcgid="" mcgrel=""
  if [ "$label" = witness ] && [ -n "$PROVING_CGROUP" ]; then
    local cg; cg="$(make_fresh_cell_cgroup)" || { rm -f "$copy"; refuse "measurement: could not establish a fresh exclusive proving cgroup"; }
    mcgrel="${cg%%$'\t'*}"; mcgid="${cg##*$'\t'}"
    cgroup_args=(--cgroup-parent "$mcgrel")
  fi
  local -a rw=(run --rm --pull never --network none --read-only
    --cap-drop ALL --security-opt no-new-privileges "${cgroup_args[@]}" --tmpfs /tmp:rw,nosuid,nodev,noexec,size=1g
    --mount "type=bind,source=$c_canon,target=/circuit,readonly"
    --mount "type=bind,source=$copy,target=$inp_target"
    --mount "type=bind,source=$o_canon,target=/output"
    "$ref" "${cargs[@]}")
  local rewritten="${rw[*]}"
  run_real "${rw[@]}"; local st=$?
  [ -n "${B0PRE_DIAG:-}" ] && { mkdir -p "$B0PRE_DIAG"; cp -f "$o_canon" "$B0PRE_DIAG/$label-output.bin" 2>/dev/null; printf '%s status=%s output_size=%s\n' "$label" "$st" "$(wc -c <"$o_canon" 2>/dev/null)" >> "$B0PRE_DIAG/diag.log"; }
  local copy_post canon_post outh
  copy_post="$(sha "$copy")"; canon_post="$(sha "$inp_canon")"
  outh="output:$(sha "$o_canon"):size:$(wc -c <"$o_canon" 2>/dev/null)"
  # ephemeral perms captured BEFORE deletion: the copy + output are the ONLY world-accessible
  # objects (fresh, per-proof); the circuit is a canonical content-store object left read-only.
  local permmap="circuit(canonical,ro):$(perms "$c_canon") ${label}_copy(ephemeral,rw):$(perms "$copy") output(ephemeral,rw):$(perms "$o_canon")"
  rm -f "$copy"
  local pre="canonical:$canon_h,copy_pre:$copy_pre" post="copy_post:$copy_post,canonical_post:$canon_post"
  # Measurement: read the PROVE container's peak from its FRESH per-cell cgroup; fail closed
  # if unavailable OR zero (never emit an unmeasured/empty proving RSS). Then remove the cell cgroup.
  if [ -n "$mcgid" ]; then
    mpeak="$(read_cgroup_peak "$mcgid" || true)"
    { [ -n "$mpeak" ] && [ "$mpeak" -gt 0 ] 2>/dev/null; } || { rmdir "$mcgid" 2>/dev/null; rm -f "$copy"; refuse "measurement: SP1 proving cgroup peak unavailable or zero at $mcgid"; }
    rmdir "$mcgid" 2>/dev/null || true
  fi
  [ "$canon_post" = "$canon_h" ] || { now_attest "sp1-$label" "$rewritten" "$recon" "$mmap" "$pre" "$post" "$outh" "$st" "$permmap" "$mpeak" "$mcgid"; refuse "CANONICAL SP1 $label input was mutated (it was never mounted)"; }
  now_attest "sp1-$label" "$rewritten" "$recon" "$mmap" "$pre" "$post" "$outh" "$st" "$permmap" "$mpeak" "$mcgid"
  exit "$st"
}

# ---- candidate detection by IMAGE (SP1 has TWO grammars: prove + verify) --------------------
is_sp1=0; is_r0=0
case "$IMAGE" in ghcr.io/succinctlabs/sp1-gnark@sha256:*|ghcr.io/succinctlabs/sp1-gnark:*) is_sp1=1 ;; esac
case "$IMAGE" in "$R0_SDK_IMAGE"|risczero/risc0-groth16-prover@sha256:*) is_r0=1 ;; esac

if [ "$is_sp1" = 1 ]; then
  [ "${#MOUNTS[@]}" = 3 ] || refuse "SP1 grammar requires exactly 3 mounts, got ${#MOUNTS[@]}"
  cs=""; ws=""; ps=""; os=""
  for m in "${MOUNTS[@]}"; do
    s="${m%:*}"; d="${m##*:}"
    case "$d" in
      /circuit) cs="$s" ;;
      /witness) ws="$s" ;;
      /proof)   ps="$s" ;;
      /output)  os="$s" ;;
      *) refuse "SP1: unexpected mount target $d" ;;
    esac
  done
  case "${CARGS[0]:-}" in
    prove)
      [ "${CARGS[*]:-}" = "prove --system groth16 /circuit /witness /output" ] \
        || refuse "SP1 prove argv mismatch: ${CARGS[*]:-}"
      [ -n "$cs" ] && [ -n "$ws" ] && [ -n "$os" ] || refuse "SP1 prove needs /circuit /witness /output mounts"
      sp1_backend witness "$cs" "$ws" /witness "$os" -- prove --system groth16 /circuit /witness /output
      ;;
    verify)
      validate_sp1_verify_argv "${CARGS[@]}"
      [ -n "$cs" ] && [ -n "$ps" ] && [ -n "$os" ] || refuse "SP1 verify needs /circuit /proof /output mounts"
      sp1_backend proof "$cs" "$ps" /proof "$os" -- "${CARGS[@]}"
      ;;
    *) refuse "SP1 subcommand not authorized: '${CARGS[0]:-}' (only groth16 prove|verify)" ;;
  esac

elif [ "$is_r0" = 1 ]; then
  [ "$IMAGE" = "$R0_SDK_IMAGE" ] || refuse "unknown RISC Zero backend image: $IMAGE (expected the SDK tag, replaced by digest)"
  [ "${#CARGS[@]}" = 0 ] || refuse "RISC Zero grammar takes no container args, got: ${CARGS[*]}"
  work="${MOUNTS[0]%:*}"
  w_canon="$(under_root "$work" "$PROOF_DIR")" || refuse "RISC Zero /mnt work dir not under per-proof root: $work"
  # inputs seal.r0 + input.json overlaid READ-ONLY inside the one writable /mnt; proof.json is output.
  seal="$w_canon/seal.r0"; inj="$w_canon/input.json"
  [ -f "$seal" ] && [ ! -L "$seal" ] || refuse "RISC Zero input seal.r0 absent or not a regular file"
  [ -f "$inj" ]  && [ ! -L "$inj" ]  || refuse "RISC Zero input input.json absent or not a regular file"
  # DAC: the backend runs as root with --cap-drop ALL (no CAP_DAC_OVERRIDE). Make ONLY this ephemeral
  # per-proof work dir + its SDK-produced intermediates accessible (the pinned circuit is BAKED into
  # the immutable image, never mounted). Content immutability of the two inputs is still enforced by
  # the read-only overlays + hash-before/after below; only their mode (not content) is normalized.
  chmod 0777 "$w_canon"      || refuse "cannot set risc0 work dir mode"
  chmod 0644 "$seal" "$inj"  || refuse "cannot set risc0 input modes"
  DIGEST_REF="$R0_REPO@$R0_MANIFEST"
  # As in sp1_backend: propagate reconcile_oci's subshell refuse() so a failed reconciliation blocks.
  recon="$(reconcile_oci "$R0_REPO" "$R0_MANIFEST" "$R0_CONFIG")" || refuse "RISC Zero backend OCI reconciliation FAILED (see reason above); refusing to run an unreconciled backend"
  [ -n "$recon" ] || refuse "RISC Zero backend OCI reconciliation returned no result"
  pre="seal:$(sha "$seal"),input:$(sha "$inj")"
  MMAP="/mnt(rw,output)=$w_canon seal.r0(ro-overlay) input.json(ro-overlay)"
  # B0-FINAL measurement: RISC Zero's only backend call IS the stark2snark prove, so place
  # it in a FRESH, EXCLUSIVE per-cell cgroup and read its peak. No-op when unset (R5).
  declare -a r0_cgroup_args=(); r0_mpeak=""; r0_mcgid=""; r0_mcgrel=""
  if [ -n "$PROVING_CGROUP" ]; then
    r0_cg="$(make_fresh_cell_cgroup)" || refuse "measurement: could not establish a fresh exclusive proving cgroup"
    r0_mcgrel="${r0_cg%%$'\t'*}"; r0_mcgid="${r0_cg##*$'\t'}"
    r0_cgroup_args=(--cgroup-parent "$r0_mcgrel")
  fi
  declare -a RW=(run --rm --pull never --network none --read-only
    --cap-drop ALL --security-opt no-new-privileges "${r0_cgroup_args[@]}" --tmpfs /tmp:rw,nosuid,nodev,exec,size=2g
    --mount "type=bind,source=$w_canon,target=/mnt"
    --mount "type=bind,source=$seal,target=/mnt/seal.r0,readonly"
    --mount "type=bind,source=$inj,target=/mnt/input.json,readonly"
    "$DIGEST_REF")
  REWRITTEN="${RW[*]}"
  run_real "${RW[@]}"; status=$?
  post="seal:$(sha "$seal"),input:$(sha "$inj")"
  outh="proof.json:$(sha "$w_canon/proof.json")"
  # RISC0's /mnt inputs are SDK-produced ephemeral intermediates (the pinned circuit is baked into
  # the immutable image, never mounted); only this fresh per-proof work dir + its files are made
  # accessible — no canonical/content-store object is touched.
  permmap="workdir(ephemeral,rw):$(perms "$w_canon") seal.r0(ephemeral,ro-input):$(perms "$seal") input.json(ephemeral,ro-input):$(perms "$inj") proof.json(ephemeral,output):$(perms "$w_canon/proof.json")"
  if [ -n "$r0_mcgid" ]; then
    r0_mpeak="$(read_cgroup_peak "$r0_mcgid" || true)"
    { [ -n "$r0_mpeak" ] && [ "$r0_mpeak" -gt 0 ] 2>/dev/null; } || { rmdir "$r0_mcgid" 2>/dev/null; refuse "measurement: RISC Zero proving cgroup peak unavailable or zero at $r0_mcgid"; }
    rmdir "$r0_mcgid" 2>/dev/null || true
  fi
  [ "$pre" = "$post" ] || { now_attest risc0 "$REWRITTEN" "$recon" "$MMAP" "$pre" "$post" "$outh" "$status" "$permmap" "$r0_mpeak" "$r0_mcgid"; refuse "RISC Zero inputs were MUTATED during proving"; }
  now_attest risc0 "$REWRITTEN" "$recon" "$MMAP" "$pre" "$post" "$outh" "$status" "$permmap" "$r0_mpeak" "$r0_mcgid"
  exit "$status"
fi

refuse "docker run does not match either authorized backend grammar (SP1 gnark prove / RISC Zero shrink_wrap)"
