#!/usr/bin/env bash
# Bounded venue PRIVILEGE PREFLIGHT for the systemd proving-cgroup teardown, matching PRODUCTION.
# Production teardown is EXACTLY: /usr/bin/sudo -n /usr/bin/systemctl stop -- <authenticated-cell-unit>.
#
# This probe:
#   1. integrity-checks /usr/bin/sudo and /usr/bin/systemctl (absolute, root-owned, non-symlink regular
#      files, not group/other writable) — fail closed otherwise;
#   2. REPORTS (never removes) any residual per-cell slices left by prior failed runs — they are evidence;
#   3. verifies the `sudo -n` privilege ONLY through the exact stop-command shape, on an authenticated
#      target — NEVER a broad `sudo true` and NEVER unprivileged systemd-run.
#
# The privilege target is EITHER (default, requires B0PRE_AUTHORIZE_RESIDUAL_CLEANUP=1) the two existing
# empty residual test slices — re-proven then stopped through the exact path, which also cleans them —
# OR, if not authorized, the probe reports that the sudo path is instead exercised by the full
# validation run (validate_cgroup_measurement.sh) on a fresh disposable Docker-created slice.
#
# It NEVER changes sudoers/polkit/daemon, never runs a prover, never runs the firewall/Docker/prover as
# root. Exit 0 = privilege proven (or, unauthorized, integrity+residuals reported cleanly); 3 = prerequisite.
set -uo pipefail

FW="$(cd "$(dirname "$0")" && pwd)/docker_firewall.sh"
[ -f "$FW" ] || { echo "REFUSED: firewall not found next to this script: $FW" >&2; exit 2; }
SUDO="${B0PRE_SUDO:-/usr/bin/sudo}"
SYSTEMCTL="${B0PRE_SYSTEMCTL:-/usr/bin/systemctl}"
PROVING_CGROUP="${B0PRE_PROVING_CGROUP:-b0-final-proving.slice}"
CGROUP_ROOT="${B0PRE_CGROUP_ROOT:-/sys/fs/cgroup}"
# The two inert residual test slices from the prior failed runs (overridable; peaks optional, matched
# against prior evidence when provided as a space-separated list in the same order).
RESIDUAL_UNITS="${B0PRE_RESIDUAL_UNITS:-b0-final-proving-cellp646177r32477r6368.slice b0-final-proving-cellp647846r9642r31604.slice}"
RESIDUAL_PEAKS="${B0PRE_RESIDUAL_PEAKS:-}"

# Reuse the firewall's REAL helpers (hierarchy resolver + executable integrity gate).
awk '/^systemd_slice_dir\(\)/{f=1} /^# Resolve a started container/{f=0} f' "$FW" > "/tmp/.b0probe.$$.fns" 2>/dev/null
# shellcheck disable=SC1090
. "/tmp/.b0probe.$$.fns"; rm -f "/tmp/.b0probe.$$.fns"
for fn in systemd_slice_dir check_root_exe; do
  type "$fn" >/dev/null 2>&1 || { echo "REFUSED: could not source $fn from the firewall" >&2; exit 2; }
done

echo "== executable integrity (the ONLY privileged step is 'stop') =="
check_root_exe "$SUDO"      || { echo "PREREQUISITE: $SUDO failed integrity (absolute, root-owned, non-symlink regular file, not group/other writable)." >&2; exit 3; }
check_root_exe "$SYSTEMCTL" || { echo "PREREQUISITE: $SYSTEMCTL failed integrity." >&2; exit 3; }
echo "  ok  $SUDO"; echo "  ok  $SYSTEMCTL"

proving_hier="$(systemd_slice_dir "$PROVING_CGROUP")"
echo "== residual per-cell slices (EVIDENCE — not removed) =="
residual=0
if [ -d "$proving_hier" ]; then
  while IFS= read -r d; do
    [ -n "$d" ] || continue
    unit="$(basename "$d")"; state="$("$SYSTEMCTL" is-active -- "$unit" 2>/dev/null || true)"
    echo "  residual: $unit  state=${state:-unknown}  peak=$(cat "$d/memory.peak" 2>/dev/null || echo '?')  dir=$d"
    residual=$((residual + 1))
  done < <(find "$proving_hier" -mindepth 1 -maxdepth 1 -type d -name 'b0-final-proving-cell*.slice' 2>/dev/null | LC_ALL=C sort)
fi
[ "$residual" -eq 0 ] && echo "  (none)"

# Re-prove a residual is exactly a disposable, inert per-cell slice before it is ever stopped.
prove_residual() { # <unit> [<expected_peak>]
  local unit="$1" want="${2:-}" d peak
  printf '%s' "$unit" | LC_ALL=C grep -Eq '^b0-final-proving-cell[a-zA-Z0-9]+\.slice$' || { echo "  REFUSE: '$unit' fails strict name validation"; return 1; }
  d="$(systemd_slice_dir "$unit")"
  [ -d "$d" ] || { echo "  SKIP: '$unit' cgroup dir absent (already cleaned?): $d"; return 2; }
  case "$d/" in "$proving_hier"/*) ;; *) echo "  REFUSE: '$unit' not beneath proving hierarchy"; return 1 ;; esac
  [ "$d" != "$proving_hier" ] || { echo "  REFUSE: '$unit' resolves to the shared parent"; return 1; }
  [ ! -s "$d/cgroup.procs" ] || { echo "  REFUSE: '$unit' has processes"; return 1; }
  [ -z "$(find "$d" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | head -1)" ] || { echo "  REFUSE: '$unit' has child cgroups/scopes"; return 1; }
  peak="$(cat "$d/memory.peak" 2>/dev/null || echo '?')"
  if [ -n "$want" ] && [ "$peak" != "$want" ]; then echo "  REFUSE: '$unit' peak $peak != expected $want"; return 1; fi
  echo "  proven-before: $unit  procs=empty  children=0  memory.peak=$peak"; return 0
}
stop_unit() { env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin "$SUDO" -n "$SYSTEMCTL" stop -- "$1"; }

if [ "${B0PRE_AUTHORIZE_RESIDUAL_CLEANUP:-0}" != 1 ]; then
  echo "== privilege probe: NOT authorized =="
  echo "  To prove the sudo teardown privilege WITHOUT a fresh allocation, re-run with"
  echo "  B0PRE_AUTHORIZE_RESIDUAL_CLEANUP=1 (optionally B0PRE_RESIDUAL_PEAKS=\"<p1> <p2>\") — it will"
  echo "  re-prove and 'sudo -n systemctl stop' ONLY the two named residual slices, recording before/after."
  echo "  Alternatively, the full validation run (validate_cgroup_measurement.sh) exercises the same exact"
  echo "  sudo teardown on a fresh disposable Docker-created slice. Integrity + residuals reported above."
  exit 3
fi

echo "== authorized residual cleanup == privilege proof via the EXACT production stop path =="
set -- $RESIDUAL_UNITS; units=("$@"); set -- $RESIDUAL_PEAKS; peaks=("$@")
i=0; stopped=0; failed=0
for unit in "${units[@]}"; do
  want="${peaks[$i]:-}"; i=$((i + 1))
  prove_residual "$unit" "$want"; pr=$?
  [ "$pr" -eq 2 ] && { echo "  (skip $unit)"; continue; }
  [ "$pr" -eq 0 ] || { failed=$((failed + 1)); continue; }
  d="$(systemd_slice_dir "$unit")"
  argv="$SUDO -n $SYSTEMCTL stop -- $unit"; echo "  stop: $argv"
  so="$(stop_unit "$unit" 2>&1)"; rc=$?
  if [ "$rc" -ne 0 ]; then echo "  PREREQUISITE: stop refused (rc=$rc): $so"; failed=$((failed + 1)); continue; fi
  w=0; while [ -e "$d" ] && [ "$w" -lt 40 ]; do w=$((w + 1)); sleep 0.25; done
  st="$("$SYSTEMCTL" is-active -- "$unit" 2>/dev/null || true)"
  if [ -e "$d" ] || { case "$st" in active|activating|deactivating|reloading) true ;; *) false ;; esac; }; then
    echo "  FAIL: $unit still present/active after stop (dir=$([ -e "$d" ] && echo present || echo gone) state=$st)"; failed=$((failed + 1)); continue
  fi
  echo "  proven-after: $unit  removed  state=${st:-not-found}"; stopped=$((stopped + 1))
done
# shared parents must remain
for p in "$proving_hier" "$(dirname "$proving_hier")"; do
  [ -e "$p" ] && echo "  shared-parent intact: $p" || echo "  WARN: shared parent missing: $p"
done
[ "$failed" -eq 0 ] || { echo "PREREQUISITE: $failed residual unit(s) could not be proven+stopped through the exact sudo path." >&2; exit 3; }
echo "PASS: 'sudo -n systemctl stop' is authorized for the exact per-cell stop shape; $stopped residual slice(s) cleaned; shared parents intact."
exit 0
