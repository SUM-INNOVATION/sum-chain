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

# Detect Docker's DAEMON cgroup driver. Prints "systemd" | "cgroupfs". Fail closed on anything
# else: an unrecognized/undetected driver means unknown peak semantics, so measurement must not run.
detect_cgroup_driver() {
  local d; d="$(run_real info --format '{{.CgroupDriver}}' 2>/dev/null)"
  case "$d" in
    systemd|cgroupfs) printf '%s' "$d" ;;
    *) echo "REFUSED: unknown/undetected Docker cgroup driver: '${d:-<none>}'" >&2; return 1 ;;
  esac
}

# systemd driver ONLY: derive a fresh, unique, SLASH-FREE child slice name of the delegated proving
# parent. systemd encodes hierarchy in the '-'-separated name, so `<stem>-cellNONCE.slice` is a
# descendant of `<stem>.slice` (== $PROVING_CGROUP). The nonce is alnum-only (a '-' would insert an
# extra systemd hierarchy level). Fail closed unless the proving parent is itself a `*.slice`, and
# require the slice name to be absent everywhere under the cgroup root (freshness). Prints the name.
make_fresh_cell_slice() {
  [ -n "$PROVING_CGROUP" ] || { echo "REFUSED: B0PRE_PROVING_CGROUP unset for measurement" >&2; return 1; }
  local base; base="$(basename "$PROVING_CGROUP")"
  case "$base" in
    *.slice) ;;
    *) echo "REFUSED: systemd driver requires B0PRE_PROVING_CGROUP to be a *.slice, got: $PROVING_CGROUP" >&2; return 1 ;;
  esac
  local stem="${base%.slice}"
  # B0PRE_CELL_NONCE is a TEST-ONLY determinism hook (unset in production -> random). A predictable
  # cell name is harmless: the per-cell slice is still freshness-checked + hierarchy-authenticated.
  local nonce; nonce="${B0PRE_CELL_NONCE:-$(printf '%s' "p$$r${RANDOM}r${RANDOM}" | tr -cd 'a-zA-Z0-9')}"
  nonce="$(printf '%s' "$nonce" | tr -cd 'a-zA-Z0-9')"
  [ -n "$nonce" ] || { echo "REFUSED: could not derive a cell-slice nonce" >&2; return 1; }
  local slice="${stem}-cell${nonce}.slice"
  if find "$CGROUP_ROOT" -type d -name "$slice" -print -quit 2>/dev/null | grep -q .; then
    echo "REFUSED: fresh cell slice already present (not fresh): $slice" >&2; return 1
  fi
  printf '%s' "$slice"
}

# systemd hierarchy semantics: a slice named `a-b-c.slice` lives at
# $CGROUP_ROOT/a.slice/a-b.slice/a-b-c.slice (each '-' is ONE hierarchy level). Resolve a slice NAME
# to its canonical cgroup-v2 directory. This is DELIBERATELY not the same as a manually-created flat
# $CGROUP_ROOT/<name> directory — the observed venue has BOTH a flat /sys/fs/cgroup/<parent>.slice
# (manual, unrelated) and the real systemd hierarchy; measurement must use the hierarchical one.
systemd_slice_dir() {
  local name="$1" stem rest part acc="" path="$CGROUP_ROOT"
  case "$name" in *.slice) ;; *) return 1 ;; esac
  stem="${name%.slice}"; rest="$stem"
  [ -n "$stem" ] || return 1
  while [ -n "$rest" ]; do
    part="${rest%%-*}"
    if [ "$part" = "$rest" ]; then rest=""; else rest="${rest#*-}"; fi
    [ -n "$part" ] || return 1
    if [ -z "$acc" ]; then acc="$part"; else acc="$acc-$part"; fi
    path="$path/$acc.slice"
  done
  printf '%s' "$path"
}

# STRICTLY validate the per-cell systemd unit name before it is ever passed to `systemctl stop`.
# Args: <unit> <authenticated-scope-path> <authenticated-cell-dir> <expected-proving-hierarchy>.
# The unit MUST: match exactly `b0-final-proving-cell<alnum>.slice` (no slash/space/metachar/traversal/
# wildcard/operator input); equal the basename of the authenticated per-cell dir; be the immediate
# parent of the authenticated live docker scope; resolve beneath the expected proving hierarchy; and
# its own hierarchical path must equal the authenticated cell dir (name<->path agreement). Returns 0
# only if EVERY check holds — so a stop can never target an ancestor, a shared slice, or injected input.
validate_cell_unit() {
  local unit="$1" scope="$2" cell_dir="$3" proving_hier="$4"
  printf '%s' "$unit" | LC_ALL=C grep -Eq '^b0-final-proving-cell[a-zA-Z0-9]+\.slice$' || return 1
  [ "$(basename "$cell_dir")" = "$unit" ] || return 1
  [ "$(dirname "$scope")" = "$cell_dir" ] || return 1
  case "$cell_dir/" in "$proving_hier"/*) ;; *) return 1 ;; esac
  [ "$cell_dir" != "$proving_hier" ] || return 1
  [ "$cell_dir" = "$(systemd_slice_dir "$unit")" ] || return 1
  return 0
}

# Integrity gate for a privileged executable (sudo / systemctl). It MUST be an absolute path, an
# existing REGULAR file (not a symlink), owned by root (B0PRE_EXE_OWNER overrides the expected owner
# for TESTS ONLY; the venue never sets it), and NOT writable by group or other. Returns 0 only if all
# hold — so the firewall never invokes a tamperable or attacker-writable privileged binary.
check_root_exe() {
  local p="$1" owner mode perm gw ow
  case "$p" in /*) ;; *) return 1 ;; esac
  [ -e "$p" ] || return 1
  [ -L "$p" ] && return 1
  [ -f "$p" ] || return 1
  owner="$(stat -c '%U' "$p" 2>/dev/null || stat -f '%Su' "$p" 2>/dev/null)"
  [ "$owner" = "${B0PRE_EXE_OWNER:-root}" ] || return 1
  mode="$(stat -c '%a' "$p" 2>/dev/null || stat -f '%Lp' "$p" 2>/dev/null)"
  [ -n "$mode" ] || return 1
  perm="${mode: -3}"; gw="${perm:1:1}"; ow="${perm:2:1}"
  case "$gw" in 2|3|6|7) return 1 ;; esac
  case "$ow" in 2|3|6|7) return 1 ;; esac
  [ -x "$p" ] || return 1
  return 0
}

# Resolve a started container's ACTUAL cgroup-v2 directory (never a guessed path). Preference order:
#   1. live PID inspection: docker inspect .State.Pid -> /proc/<pid>/cgroup (the kernel's own view);
#   2. fallback (container exited before we caught the PID): locate the persisted
#      `docker-<fullcid>.scope` dir by the container's real id (still present pre-removal).
# Prints the absolute dir under $CGROUP_ROOT, or returns non-zero.
capture_container_cgroup() {
  local cid="$1" i=0 pid rel status
  while [ "$i" -lt 200 ]; do
    pid="$(run_real inspect -f '{{.State.Pid}}' "$cid" 2>/dev/null)"
    if [ -n "$pid" ] && [ "$pid" -gt 0 ] 2>/dev/null && [ -r "/proc/$pid/cgroup" ]; then
      rel="$(awk -F'::' '/^0::/{print $2; exit}' "/proc/$pid/cgroup" 2>/dev/null)"
      if [ -n "$rel" ] && [ -d "$CGROUP_ROOT$rel" ]; then printf '%s' "$CGROUP_ROOT$rel"; return 0; fi
    fi
    status="$(run_real inspect -f '{{.State.Status}}' "$cid" 2>/dev/null)"
    case "$status" in exited|dead) break ;; esac
    i=$((i + 1))
  done
  local scope; scope="$(find "$CGROUP_ROOT" -type d -name "docker-$cid.scope" -print -quit 2>/dev/null)"
  [ -n "$scope" ] && { printf '%s' "$scope"; return 0; }
  return 1
}

# Execute the PROVE backend, driver-aware. $1 = measure (1|0). The remaining args (after '--') are
# the `docker run` arguments EXCLUDING the leading `run`, `--rm`, and any `--cgroup-parent` (this
# function supplies those). Sets MB_STATUS (backend exit code), MB_PEAK (peak bytes | ""), MB_CGID
# (cgroup identity | ""). Fail closed: refuses on unknown driver, ambiguous/missing scope, failed
# lifecycle, or a zero/absent peak while measuring. Sandbox flags/mounts/image are IDENTICAL across
# drivers — only how the container's peak is isolated + read differs.
run_measured_backend() {
  local measure="$1"; shift
  [ "${1:-}" = "--" ] && shift
  local -a base=("$@")
  MB_STATUS=""; MB_PEAK=""; MB_CGID=""; MB_CLEANUP_OK=1; MB_CLEANUP_DETAIL=""
  MB_TEARDOWN_ARGV=""; MB_TEARDOWN_RC=""; MB_TEARDOWN_STDERR=""

  if [ "$measure" != 1 ]; then
    run_real run --rm "${base[@]}"; MB_STATUS=$?
    return 0
  fi

  local driver; driver="$(detect_cgroup_driver)" || refuse "measurement: Docker cgroup driver detection failed"

  if [ "$driver" = cgroupfs ]; then
    # PROVEN path: pre-create a fresh EXCLUSIVE child cgroup, pass it via --cgroup-parent, read its
    # peak after the (self-removing) run. Byte-for-byte the pre-existing measurement behavior.
    local cg rel abs
    cg="$(make_fresh_cell_cgroup)" || refuse "measurement: could not establish a fresh exclusive proving cgroup (cgroupfs)"
    rel="${cg%%$'\t'*}"; abs="${cg##*$'\t'}"
    run_real run --rm --cgroup-parent "$rel" "${base[@]}"; MB_STATUS=$?
    local pk; pk="$(read_cgroup_peak "$abs" || true)"
    { [ -n "$pk" ] && [ "$pk" -gt 0 ] 2>/dev/null; } || { rmdir "$abs" 2>/dev/null; refuse "measurement: SP1/RISC0 proving cgroup peak unavailable or zero at $abs (cgroupfs)"; }
    rmdir "$abs" 2>/dev/null || true
    MB_PEAK="$pk"; MB_CGID="cgroupfs:$abs"
    return 0
  fi

  # driver == systemd: Docker places the container in a systemd-managed hierarchy — NOT under a
  # manually-created flat $CGROUP_ROOT/<parent>.slice dir — and `--rm` tears down the transient
  # docker-<id>.scope (and its memory.peak) before it can be read. Translate the authorized run into a
  # create/start/inspect/wait/read/remove lifecycle: resolve the container's OWN scope from its live
  # PID, authenticate it against the EXPECTED systemd hierarchy, and read the peak from the UNIQUE
  # PER-CELL SLICE (which aggregates exactly this one container and survives briefly after the child
  # scope exits). Never substitute an ancestor/shared-slice peak.
  local cell name cid cell_dir proving_hier
  cell="$(make_fresh_cell_slice)" || refuse "measurement: could not derive a fresh proving cell slice (systemd)"
  cell_dir="$(systemd_slice_dir "$cell")" || refuse "measurement: could not resolve systemd hierarchy for cell slice $cell (systemd)"
  proving_hier="$(systemd_slice_dir "$(basename "$PROVING_CGROUP")")" || refuse "measurement: could not resolve systemd hierarchy for proving parent $PROVING_CGROUP (systemd)"
  # Freshness at the EXPECTED hierarchical path (NOT the flat manual dir): the per-cell slice must not
  # pre-exist.
  [ ! -e "$cell_dir" ] || refuse "measurement: per-cell slice already present (not fresh): $cell_dir (systemd)"
  name="b0prove-$$-${RANDOM}${RANDOM}"
  run_real inspect "$name" >/dev/null 2>&1 && refuse "measurement: proving container name already exists: $name (systemd)"
  cid="$(run_real create --name "$name" --cgroup-parent "$cell" "${base[@]}" 2>/dev/null)" \
    || refuse "measurement: could not create proving container under slice $cell (systemd)"
  [ -n "$cid" ] || refuse "measurement: empty container id from docker create (systemd)"
  [ ! -e "$cell_dir/docker-$cid.scope" ] \
    || { run_real rm -f "$cid" >/dev/null 2>&1; refuse "measurement: container scope pre-exists (not fresh): $cell_dir/docker-$cid.scope (systemd)"; }
  run_real start "$cid" >/dev/null 2>&1 \
    || { run_real rm -f "$cid" >/dev/null 2>&1; refuse "measurement: could not start proving container $cid (systemd)"; }

  # Authenticate the live scope against the EXPECTED systemd hierarchy.
  local scope; scope="$(capture_container_cgroup "$cid")" \
    || { run_real rm -f "$cid" >/dev/null 2>&1; refuse "measurement: could not resolve the live proving scope (systemd)"; }
  # (1) immediate parent is exactly the unique per-cell slice at its hierarchical path;
  [ "$(dirname "$scope")" = "$cell_dir" ] \
    || { run_real rm -f "$cid" >/dev/null 2>&1; refuse "measurement: scope parent '$(dirname "$scope")' != expected per-cell slice '$cell_dir' (systemd)"; }
  # (2) it is the container's OWN scope;
  [ "$(basename "$scope")" = "docker-$cid.scope" ] \
    || { run_real rm -f "$cid" >/dev/null 2>&1; refuse "measurement: resolved scope '$(basename "$scope")' is not docker-$cid.scope (systemd)"; }
  # (3) the per-cell slice sits BENEATH the expected proving hierarchy (never the flat manual dir);
  case "$cell_dir/" in
    "$proving_hier"/*) ;;
    *) run_real rm -f "$cid" >/dev/null 2>&1; refuse "measurement: per-cell slice '$cell_dir' is not beneath the expected proving hierarchy '$proving_hier' (systemd)" ;;
  esac
  # (4) the per-cell slice contains EXACTLY ONE scope (no unrelated child aggregated into the peak).
  local nscope; nscope="$(find "$cell_dir" -mindepth 1 -maxdepth 1 -type d -name '*.scope' 2>/dev/null | wc -l | tr -d ' ')"
  { [ "$nscope" = 1 ] && [ -d "$cell_dir/docker-$cid.scope" ]; } \
    || { run_real rm -f "$cid" >/dev/null 2>&1; refuse "measurement: per-cell slice must contain exactly one scope (docker-$cid.scope), found $nscope (systemd)"; }

  # Race-safe peak: monitor the AUTHENTICATED per-cell slice's memory.peak while the container is live
  # (keep the max), read it once more after wait if it still exists, and use the max of the
  # authenticated observations. memory.peak is monotonic, so this is the true high-water mark.
  local best=0 cur running
  while :; do
    cur="$(read_cgroup_peak "$cell_dir" 2>/dev/null || true)"
    if [ -n "$cur" ] && [ "$cur" -gt "$best" ] 2>/dev/null; then best="$cur"; fi
    running="$(run_real inspect -f '{{.State.Running}}' "$cid" 2>/dev/null)"
    [ "$running" = true ] || break
    sleep 0.5
  done
  local st; st="$(run_real wait "$cid" 2>/dev/null)"
  case "$st" in ''|*[!0-9]*) run_real rm -f "$cid" >/dev/null 2>&1; refuse "measurement: could not read proving container exit code (systemd)" ;; esac
  if [ -d "$cell_dir" ]; then
    cur="$(read_cgroup_peak "$cell_dir" 2>/dev/null || true)"
    if [ -n "$cur" ] && [ "$cur" -gt "$best" ] 2>/dev/null; then best="$cur"; fi
  fi
  run_real logs "$cid" || true
  [ "$best" -gt 0 ] 2>/dev/null \
    || { run_real rm -f "$cid" >/dev/null 2>&1; refuse "measurement: no authenticated nonzero peak observed on the per-cell slice $cell_dir (systemd)"; }

  # The measurement is captured. From here a CLEANUP failure must NOT discard the workload status:
  # publish the outputs now, then tear down; on ANY teardown failure set MB_CLEANUP_OK=0 (+ detail) and
  # RETURN so the caller records the workload status in evidence before failing the measurement.
  MB_STATUS="$st"; MB_PEAK="$best"; MB_CGID="systemd:$cell(peak-from-per-cell-slice)=$cell_dir"

  # Remove the container (removes docker-<id>.scope). Docker leaves the IMPLICITLY-created per-cell
  # systemd SLICE loaded/active, so we must stop EXACTLY that unit — but only after proving it inert.
  run_real rm "$cid" >/dev/null 2>&1 || run_real rm -f "$cid" >/dev/null 2>&1 \
    || { MB_CLEANUP_OK=0; MB_CLEANUP_DETAIL="could not remove container $cid"; return 0; }
  run_real inspect "$cid" >/dev/null 2>&1 \
    && { MB_CLEANUP_OK=0; MB_CLEANUP_DETAIL="container $cid still present after rm"; return 0; }
  [ ! -e "$cell_dir/docker-$cid.scope" ] \
    || { MB_CLEANUP_OK=0; MB_CLEANUP_DETAIL="docker scope still present after rm: $cell_dir/docker-$cid.scope"; return 0; }
  if [ -d "$cell_dir" ]; then
    [ ! -s "$cell_dir/cgroup.procs" ] \
      || { MB_CLEANUP_OK=0; MB_CLEANUP_DETAIL="per-cell slice still has processes (cgroup.procs nonempty): $cell_dir"; return 0; }
    local kids; kids="$(find "$cell_dir" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | head -1)"
    [ -z "$kids" ] \
      || { MB_CLEANUP_OK=0; MB_CLEANUP_DETAIL="per-cell slice still has a child cgroup/scope: $kids"; return 0; }
  fi

  # Stop EXACTLY the authenticated per-cell unit (never an ancestor/shared slice). Strictly validate
  # the internally-generated unit name first, then use the absolute owner-approved systemctl.
  if ! validate_cell_unit "$cell" "$scope" "$cell_dir" "$proving_hier"; then
    MB_CLEANUP_OK=0; MB_CLEANUP_DETAIL="refusing systemctl stop: per-cell unit '$cell' failed strict validation"; return 0
  fi
  # Privileged teardown uses EXACTLY: /usr/bin/sudo -n /usr/bin/systemctl stop -- <cell>. Direct
  # systemd management needs interactive auth on the venue, so the ONLY privileged step (`stop`) goes
  # through a narrow passwordless-sudo rule. Integrity-check both binaries first; the post-stop
  # `is-active` reads below are UNPRIVILEGED (no sudo). Nothing else runs as root — not the firewall,
  # Docker, the prover, or the measurement process; sudo is never used for systemd-run.
  local SUDO="${B0PRE_SUDO:-/usr/bin/sudo}" SYSTEMCTL="${B0PRE_SYSTEMCTL:-/usr/bin/systemctl}"
  check_root_exe "$SUDO" \
    || { MB_CLEANUP_OK=0; MB_CLEANUP_DETAIL="sudo executable integrity check failed for '$SUDO' (must be an absolute, root-owned, non-symlink regular file, not group/other writable)"; return 0; }
  check_root_exe "$SYSTEMCTL" \
    || { MB_CLEANUP_OK=0; MB_CLEANUP_DETAIL="systemctl executable integrity check failed for '$SYSTEMCTL' (must be an absolute, root-owned, non-symlink regular file, not group/other writable)"; return 0; }
  # Built as ARGV (no shell evaluation), in a sanitized env, non-interactive (-n) so a prompt is
  # impossible. `$cell` is the internally-generated, strictly-validated unit name.
  MB_TEARDOWN_ARGV="$SUDO -n $SYSTEMCTL stop -- $cell"
  local so src; so="$(env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin "$SUDO" -n "$SYSTEMCTL" stop -- "$cell" 2>&1)"; src=$?
  MB_TEARDOWN_RC="$src"; MB_TEARDOWN_STDERR="$so"
  if [ "$src" -ne 0 ]; then
    MB_CLEANUP_OK=0; MB_CLEANUP_DETAIL="'sudo -n systemctl stop -- $cell' was refused (rc=$src): ${so}; VENUE PROVISIONING REQUIRED: a NARROW passwordless-sudo rule permitting EXACTLY '/usr/bin/systemctl stop -- b0-final-proving-cell*.slice' for the venue user (no unrestricted sudo; no sudoers/polkit change beyond that exact rule; do not run the firewall/Docker/prover as root)"; return 0
  fi
  # After stop: the unit must go inactive/not-found AND its cgroup dir must disappear (bounded wait).
  local w=0
  while [ "$w" -lt 20 ]; do
    local act; act="$("$SYSTEMCTL" is-active -- "$cell" 2>/dev/null || true)"
    case "$act" in active|activating|deactivating|reloading) ;; *) [ ! -e "$cell_dir" ] && break ;; esac
    w=$((w + 1)); sleep 0.25
  done
  local act2; act2="$("$SYSTEMCTL" is-active -- "$cell" 2>/dev/null || true)"
  case "$act2" in
    active|activating|deactivating|reloading) MB_CLEANUP_OK=0; MB_CLEANUP_DETAIL="per-cell unit $cell still '$act2' after stop"; return 0 ;;
  esac
  [ ! -e "$cell_dir" ] \
    || { MB_CLEANUP_OK=0; MB_CLEANUP_DETAIL="per-cell cgroup dir remains after stop: $cell_dir"; return 0; }
  [ ! -e "$cell_dir/docker-$cid.scope" ] \
    || { MB_CLEANUP_OK=0; MB_CLEANUP_DETAIL="scope reappeared after stop"; return 0; }
  run_real inspect "$cid" >/dev/null 2>&1 \
    && { MB_CLEANUP_OK=0; MB_CLEANUP_DETAIL="container reappeared after stop"; return 0; }
  # The shared proving hierarchy (proving/final/root slices) was never targeted and remains loaded.
  MB_CGID="systemd:$cell(peak-from-per-cell-slice;unit-stopped)=$cell_dir"
  return 0
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
  # B0-FINAL measurement: place the PROVE (witness) container in a FRESH, EXCLUSIVE per-cell cgroup
  # so its PEAK memory is isolated; the verify (proof) call is left unmeasured. Driver-aware inside
  # run_measured_backend (cgroupfs keeps the pre-created child + `run --rm`; systemd uses a
  # create/start/inspect/wait/remove lifecycle). No-op when PROVING_CGROUP is unset (R5 / verify).
  local measure=0
  { [ "$label" = witness ] && [ -n "$PROVING_CGROUP" ]; } && measure=1
  local -a base=(--pull never --network none --read-only
    --cap-drop ALL --security-opt no-new-privileges --tmpfs /tmp:rw,nosuid,nodev,noexec,size=1g
    --mount "type=bind,source=$c_canon,target=/circuit,readonly"
    --mount "type=bind,source=$copy,target=$inp_target"
    --mount "type=bind,source=$o_canon,target=/output"
    "$ref" "${cargs[@]}")
  local rewritten="run --rm ${base[*]}"
  run_measured_backend "$measure" -- "${base[@]}"
  local st="$MB_STATUS" mpeak="$MB_PEAK" mcgid="$MB_CGID"
  [ -n "${B0PRE_DIAG:-}" ] && { mkdir -p "$B0PRE_DIAG"; cp -f "$o_canon" "$B0PRE_DIAG/$label-output.bin" 2>/dev/null; printf '%s status=%s output_size=%s\n' "$label" "$st" "$(wc -c <"$o_canon" 2>/dev/null)" >> "$B0PRE_DIAG/diag.log"; }
  local copy_post canon_post outh
  copy_post="$(sha "$copy")"; canon_post="$(sha "$inp_canon")"
  outh="output:$(sha "$o_canon"):size:$(wc -c <"$o_canon" 2>/dev/null)"
  # ephemeral perms captured BEFORE deletion: the copy + output are the ONLY world-accessible
  # objects (fresh, per-proof); the circuit is a canonical content-store object left read-only.
  local permmap="circuit(canonical,ro):$(perms "$c_canon") ${label}_copy(ephemeral,rw):$(perms "$copy") output(ephemeral,rw):$(perms "$o_canon")"
  rm -f "$copy"
  local pre="canonical:$canon_h,copy_pre:$copy_pre" post="copy_post:$copy_post,canonical_post:$canon_post"
  [ "$canon_post" = "$canon_h" ] || { now_attest "sp1-$label" "$rewritten" "$recon" "$mmap" "$pre" "$post" "$outh" "$st" "$permmap" "$mpeak" "$mcgid"; refuse "CANONICAL SP1 $label input was mutated (it was never mounted)"; }
  now_attest "sp1-$label" "$rewritten" "$recon" "$mmap" "$pre" "$post" "$outh" "$st" "$permmap" "$mpeak" "$mcgid"
  # Cleanup failure fails the measurement, but the workload status ($st) is already retained in the
  # attestation above.
  [ "${MB_CLEANUP_OK:-1}" = 1 ] || refuse "measurement cleanup FAILED (SP1 $label workload exit $st retained in attestation): ${MB_CLEANUP_DETAIL:-}"
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
  # B0-FINAL measurement: RISC Zero's only backend call IS the stark2snark prove, so place it in a
  # FRESH, EXCLUSIVE per-cell cgroup and read its peak (driver-aware inside run_measured_backend:
  # cgroupfs keeps the pre-created child + `run --rm`; systemd uses a create/start/inspect/wait/remove
  # lifecycle). No-op when PROVING_CGROUP is unset (R5).
  r0_measure=0
  [ -n "$PROVING_CGROUP" ] && r0_measure=1
  declare -a r0_base=(--pull never --network none --read-only
    --cap-drop ALL --security-opt no-new-privileges --tmpfs /tmp:rw,nosuid,nodev,exec,size=2g
    --mount "type=bind,source=$w_canon,target=/mnt"
    --mount "type=bind,source=$seal,target=/mnt/seal.r0,readonly"
    --mount "type=bind,source=$inj,target=/mnt/input.json,readonly"
    "$DIGEST_REF")
  REWRITTEN="run --rm ${r0_base[*]}"
  run_measured_backend "$r0_measure" -- "${r0_base[@]}"
  status="$MB_STATUS"; r0_mpeak="$MB_PEAK"; r0_mcgid="$MB_CGID"
  post="seal:$(sha "$seal"),input:$(sha "$inj")"
  outh="proof.json:$(sha "$w_canon/proof.json")"
  # RISC0's /mnt inputs are SDK-produced ephemeral intermediates (the pinned circuit is baked into
  # the immutable image, never mounted); only this fresh per-proof work dir + its files are made
  # accessible — no canonical/content-store object is touched.
  permmap="workdir(ephemeral,rw):$(perms "$w_canon") seal.r0(ephemeral,ro-input):$(perms "$seal") input.json(ephemeral,ro-input):$(perms "$inj") proof.json(ephemeral,output):$(perms "$w_canon/proof.json")"
  # (the fresh proving cgroup's peak is captured + verified nonzero inside run_measured_backend)
  [ "$pre" = "$post" ] || { now_attest risc0 "$REWRITTEN" "$recon" "$MMAP" "$pre" "$post" "$outh" "$status" "$permmap" "$r0_mpeak" "$r0_mcgid"; refuse "RISC Zero inputs were MUTATED during proving"; }
  now_attest risc0 "$REWRITTEN" "$recon" "$MMAP" "$pre" "$post" "$outh" "$status" "$permmap" "$r0_mpeak" "$r0_mcgid"
  # Cleanup failure fails the measurement, but the workload status ($status) is already retained above.
  [ "${MB_CLEANUP_OK:-1}" = 1 ] || refuse "measurement cleanup FAILED (RISC Zero workload exit $status retained in attestation): ${MB_CLEANUP_DETAIL:-}"
  exit "$status"
fi

refuse "docker run does not match either authorized backend grammar (SP1 gnark prove / RISC Zero shrink_wrap)"
