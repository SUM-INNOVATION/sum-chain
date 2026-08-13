#!/usr/bin/env bash
# Driver-aware cgroup measurement unit test for docker_firewall.sh. Extracts the measurement helpers
# and drives them with STUB docker + STUB sudo + STUB systemctl that simulate the OBSERVED systemd
# hierarchy and the PRIVILEGED teardown, so the corrected lifecycle is exercised WITHOUT a real daemon
# and independent of host arch.
#
# Corrections under test (from the three failed x86 venue runs):
#   v2: peak from the hierarchical PER-CELL SLICE, authenticated.
#   v3: after `docker rm` (scope), stop EXACTLY the authenticated per-cell unit; status-preserving.
#   v4: the ONLY privileged step is `/usr/bin/sudo -n /usr/bin/systemctl stop -- <unit>`, built as argv
#       in a sanitized env; sudo+systemctl are integrity-checked (root-owned, non-symlink, non-writable);
#       no privileged command runs before full authentication.
#
# The stub sudo/systemctl read config from $WORK/sc.conf (with baked absolute paths) because production
# invokes sudo under `env -i` — which clears env — so env-based stub config would not survive.
#
# NOTE: mocks alone do not close item D — the real sudo teardown + privilege are proven on the x86 venue
# by probe_cgroup_privilege.sh + validate_cgroup_measurement.sh before Commit A.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
FW="$HERE/../docker_firewall.sh"
fails=0
ok()   { printf 'ok    %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1"; fails=$((fails+1)); }
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

awk '/^detect_cgroup_driver\(\)/{f=1} /^# --- recursion guard/{f=0} f' "$FW" > "$WORK/fns.sh"
for fn in run_measured_backend systemd_slice_dir validate_cell_unit check_root_exe; do
  grep -q "^$fn()" "$WORK/fns.sh" || { echo "FAIL  $fn not extracted"; exit 1; }
done

export CGROUP_ROOT="$WORK/cg"; mkdir -p "$CGROUP_ROOT"
PROVING_CGROUP="b0-final-proving.slice"
refuse() { echo "FIREWALL-REFUSED: $*" >&2; exit 97; }
read_cgroup_peak() { local d="$1"; [ -n "$d" ] || return 1; [ -f "$d/memory.peak" ] && cat "$d/memory.peak" 2>/dev/null || return 1; }
make_fresh_cell_cgroup() { local abs="$CGROUP_ROOT/$PROVING_CGROUP/cell-$$-$RANDOM"; mkdir -p "$abs"; echo "${CGFS_PEAK:-4096}" > "$abs/memory.peak"; printf '%s\t%s' "$PROVING_CGROUP/$(basename "$abs")" "$abs"; }

# --- stub systemctl (baked CGROUP_ROOT + config path; survives `env -i`) ---
cat > "$WORK/systemctl" <<EOF
#!/usr/bin/env bash
CR="$CGROUP_ROOT"; [ -f "$WORK/sc.conf" ] && . "$WORK/sc.conf"
sdir(){ local n="\$1" stem rest part acc="" p="\$CR"; case "\$n" in *.slice) ;; *) return 1;; esac; stem="\${n%.slice}"; rest="\$stem"; while [ -n "\$rest" ]; do part="\${rest%%-*}"; if [ "\$part" = "\$rest" ]; then rest=""; else rest="\${rest#*-}"; fi; if [ -z "\$acc" ]; then acc="\$part"; else acc="\$acc-\$part"; fi; p="\$p/\$acc.slice"; done; printf '%s' "\$p"; }
case "\$1" in
  stop) echo "\$3" >> "$WORK/sc.stops"; [ "\${SC_STOP_RC:-0}" = 0 ] || { echo "stop failed" >&2; exit "\${SC_STOP_RC}"; }; [ "\${SC_LEAVE_DIR:-0}" = 1 ] || rm -rf "\$(sdir "\$3")"; exit 0 ;;
  is-active) printf '%s' "\${SC_ACTIVE:-inactive}"; exit 0 ;;
  *) exit 0 ;;
esac
EOF
chmod 755 "$WORK/systemctl"
# --- stub sudo (records full argv; validates -n; refuse configurable; then exec's the target) ---
cat > "$WORK/sudo" <<EOF
#!/usr/bin/env bash
[ -f "$WORK/sc.conf" ] && . "$WORK/sc.conf"
printf '%s\n' "\$*" >> "$WORK/sudo.calls"
[ "\$1" = "-n" ] || { echo "sudo: -n required" >&2; exit 2; }
[ "\${SUDO_REFUSE:-0}" = 1 ] && { echo "sudo: a password is required" >&2; exit 1; }
shift; exec "\$@"
EOF
chmod 755 "$WORK/sudo"
export B0PRE_SUDO="$WORK/sudo" B0PRE_SYSTEMCTL="$WORK/systemctl" B0PRE_EXE_OWNER="$(id -un)"

# --- stub docker: `rm` removes ONLY the scope (Docker leaves the slice loaded) ---
run_real() {
  local sub="$1"; shift
  case "$sub" in
    info) printf '%s' "${DRIVER:-systemd}" ;;
    run)  return "${RUN_EXIT:-0}" ;;
    inspect)
      if [ "${1:-}" = "-f" ]; then case "$2" in *State.Pid*) echo 0 ;; *State.Status*) echo exited ;; *State.Running*) echo false ;; esac; return 0; fi
      return 1 ;;
    create)
      local slice=""; while [ "$#" -gt 0 ]; do case "$1" in --cgroup-parent) slice="$2"; shift 2;; *) shift;; esac; done
      printf '%s' "$slice" > "$WORK/slice"; local nonce cid; nonce="${slice##*-cell}"; nonce="${nonce%.slice}"; cid="cid${nonce}"; printf '%s' "$cid" > "$WORK/cid"
      [ "${CREATE_MAKES_SCOPE:-0}" = 1 ] && mkdir -p "$(systemd_slice_dir "$slice")/docker-$cid.scope"
      printf '%s' "$cid" ;;
    start)
      local slice cd cid; slice="$(cat "$WORK/slice")"; cid="$(cat "$WORK/cid")"; cd="$(systemd_slice_dir "$slice")"; mkdir -p "$cd"
      [ "${SYSD_NO_PEAK:-0}" = 1 ] || printf '%s' "${SYSD_PEAK:-987654321}" > "$cd/memory.peak"
      if [ "${SYSD_NONEMPTY:-0}" = 1 ]; then printf '12345\n' > "$cd/cgroup.procs"; else : > "$cd/cgroup.procs"; fi
      case "${SCOPE_LOC:-cell}" in cell) mkdir -p "$cd/docker-$cid.scope" ;; wrong) mkdir -p "$CGROUP_ROOT/docker-$cid.scope" ;; none) : ;; esac
      [ "${EXTRA_SCOPE:-0}" = 1 ] && mkdir -p "$cd/docker-${cid}extra.scope"
      return 0 ;;
    wait) printf '%s' "${SYSD_EXIT:-0}" ;;
    logs) : ;;
    rm)   local slice cd cid; slice="$(cat "$WORK/slice" 2>/dev/null)"; cid="$(cat "$WORK/cid" 2>/dev/null)"; [ -n "$slice" ] && { cd="$(systemd_slice_dir "$slice")"; rm -rf "$cd/docker-$cid.scope"; }; return 0 ;;
    *)    return 9 ;;
  esac
}
# shellcheck disable=SC1090
. "$WORK/fns.sh"
: > "$WORK/sc.conf"

# ---- unit-name validation + executable integrity ----
PH="$CGROUP_ROOT/b0.slice/b0-final.slice/b0-final-proving.slice"; CDX="$PH/b0-final-proving-cellX.slice"; SCX="$CDX/docker-abc.scope"
validate_cell_unit "b0-final-proving-cellX.slice" "$SCX" "$CDX" "$PH" && ok "validate_cell_unit: valid" || fail "valid unit rejected"
for bad in 'b0-final-proving-cellX.slice/../etc' 'b0-final-proving-cell*.slice' 'b0-final-proving-cell X.slice' 'b0-final-proving-cellX.slice; rm -rf /' '../b0-final-proving-cellX.slice' 'evil.slice'; do
  validate_cell_unit "$bad" "$SCX" "$CDX" "$PH" && fail "malicious unit accepted: $bad" || ok "invalid/mismatched unit rejected: $bad"
done
validate_cell_unit "b0-final-proving.slice" "$PH/docker-abc.scope" "$PH" "$PH" && fail "shared parent accepted" || ok "shared-parent target rejected"
# check_root_exe: happy (test-owned, 755) + integrity negatives
check_root_exe "$WORK/sudo" && ok "check_root_exe: valid exe accepted" || fail "valid exe rejected"
check_root_exe "relative/systemctl" && fail "relative accepted" || ok "check_root_exe: relative path rejected"
ln -sf "$WORK/systemctl" "$WORK/sysln"; check_root_exe "$WORK/sysln" && fail "symlink accepted" || ok "check_root_exe: symlink rejected"
check_root_exe "$CGROUP_ROOT" && fail "dir accepted" || ok "check_root_exe: non-regular rejected"
check_root_exe "$WORK/missing" && fail "missing accepted" || ok "check_root_exe: missing rejected"
cp "$WORK/sudo" "$WORK/wsudo"; chmod 777 "$WORK/wsudo"; check_root_exe "$WORK/wsudo" && fail "writable accepted" || ok "check_root_exe: group/other-writable rejected"
( unset B0PRE_EXE_OWNER; check_root_exe "$WORK/sudo" ) && fail "non-root-owner accepted" || ok "check_root_exe: non-root-owned rejected (default owner=root)"

# ---- HAPPY PATH: per-cell peak; sudo -n systemctl stop EXACT argv; only cell unit; clean ----
mkdir -p "$CGROUP_ROOT/$PROVING_CGROUP"; printf '111' > "$CGROUP_ROOT/$PROVING_CGROUP/memory.peak"
: > "$WORK/sudo.calls"; : > "$WORK/sc.stops"; : > "$WORK/sc.conf"
DRIVER=systemd SYSD_PEAK=70516736 SYSD_EXIT=0 B0PRE_CELL_NONCE=hp1
run_measured_backend 1 -- --pull never img args
[ "$MB_STATUS" = 0 ] && ok "workload status preserved" || fail "status ($MB_STATUS)"
[ "$MB_PEAK" = 70516736 ] && ok "peak from per-cell slice" || fail "peak ($MB_PEAK)"
[ "${MB_CLEANUP_OK:-x}" = 1 ] && ok "cleanup OK via sudo stop" || fail "cleanup ($MB_CLEANUP_DETAIL)"
[ ! -e "$(systemd_slice_dir b0-final-proving-cellhp1.slice)" ] && ok "per-cell slice removed" || fail "cell remains"
exp_argv="-n $WORK/systemctl stop -- b0-final-proving-cellhp1.slice"
[ "$(cat "$WORK/sudo.calls")" = "$exp_argv" ] && ok "sudo argv is EXACTLY '-n <systemctl> stop -- <cell>' (no injection)" || fail "sudo argv: $(cat "$WORK/sudo.calls")"
[ "$MB_TEARDOWN_ARGV" = "$WORK/sudo -n $WORK/systemctl stop -- b0-final-proving-cellhp1.slice" ] && ok "teardown argv attested" || fail "teardown argv ($MB_TEARDOWN_ARGV)"
grep -qE 'b0-final-proving\.slice|b0-final\.slice|/b0\.slice$' "$WORK/sc.stops" && fail "stopped a shared parent" || ok "shared parents never stopped"
unset B0PRE_CELL_NONCE

neg(){ grep -q "$2" "$WORK/e" && ok "neg: $1" || fail "neg: $1 (missing '$2'): $(head -1 "$WORK/e")"; }
# --- authentication negatives refuse BEFORE any privileged command ---
: > "$WORK/sudo.calls"
( DRIVER=systemd SCOPE_LOC=wrong B0PRE_CELL_NONCE=a1 run_measured_backend 1 -- --pull never i a ) >/dev/null 2>"$WORK/e"; neg "scope outside hierarchy" "!= expected per-cell slice"
[ ! -s "$WORK/sudo.calls" ] && ok "NO privileged command before full authentication" || fail "sudo invoked before auth passed"
( DRIVER=systemd SYSD_PEAK=0 B0PRE_CELL_NONCE=a2 run_measured_backend 1 -- --pull never i a ) >/dev/null 2>"$WORK/e"; neg "zero peak" "no authenticated nonzero peak"
( DRIVER=systemd EXTRA_SCOPE=1 B0PRE_CELL_NONCE=a3 run_measured_backend 1 -- --pull never i a ) >/dev/null 2>"$WORK/e"; neg "multiple scopes" "exactly one scope"

# --- v4 teardown negatives (measurement OK, cleanup fails, workload status retained) ---
tf(){ [ "${MB_CLEANUP_OK:-1}" = 0 ] || { fail "tf: $1 (cleanup unexpectedly ok)"; return; }; [ "$MB_STATUS" = 0 ] || { fail "tf: $1 (status not retained: $MB_STATUS)"; return; }; case "$MB_CLEANUP_DETAIL" in *"$2"*) ok "tf: $1 (fails cleanup, status retained)";; *) fail "tf: $1 (detail '$MB_CLEANUP_DETAIL' lacks '$2')";; esac; }
printf 'SUDO_REFUSE=1\n' > "$WORK/sc.conf"; DRIVER=systemd SYSD_EXIT=0 B0PRE_CELL_NONCE=t1 run_measured_backend 1 -- --pull never i a; tf "sudo prompt/refusal" "was refused (rc=1)"
printf 'SC_STOP_RC=5\n' > "$WORK/sc.conf"; DRIVER=systemd SYSD_EXIT=0 B0PRE_CELL_NONCE=t2 run_measured_backend 1 -- --pull never i a; tf "sudo stop failure (rc!=0)" "was refused (rc=5)"
printf 'SC_ACTIVE=active\n' > "$WORK/sc.conf"; DRIVER=systemd SYSD_EXIT=0 B0PRE_CELL_NONCE=t3 run_measured_backend 1 -- --pull never i a; tf "unit remains active" "still 'active'"
printf 'SC_LEAVE_DIR=1\n' > "$WORK/sc.conf"; DRIVER=systemd SYSD_EXIT=0 B0PRE_CELL_NONCE=t4 run_measured_backend 1 -- --pull never i a; tf "cgroup dir remains after inactive" "cgroup dir remains after stop"
: > "$WORK/sc.conf"; DRIVER=systemd SYSD_EXIT=0 SYSD_NONEMPTY=1 B0PRE_CELL_NONCE=t5 run_measured_backend 1 -- --pull never i a; tf "nonempty cell before stop" "still has processes"
# integrity failure of sudo/systemctl fails closed (bad B0PRE_SUDO path)
B0PRE_SUDO="$WORK/nonexistent-sudo" DRIVER=systemd SYSD_EXIT=0 B0PRE_CELL_NONCE=t6 run_measured_backend 1 -- --pull never i a; tf "sudo integrity failure" "sudo executable integrity check failed"
ln -sf "$WORK/systemctl" "$WORK/sysln2"; B0PRE_SYSTEMCTL="$WORK/sysln2" DRIVER=systemd SYSD_EXIT=0 B0PRE_CELL_NONCE=t7 run_measured_backend 1 -- --pull never i a; tf "systemctl symlink integrity failure" "systemctl executable integrity check failed"
# original status preserved on SUCCESSFUL teardown
: > "$WORK/sc.conf"; DRIVER=systemd SYSD_EXIT=0 B0PRE_CELL_NONCE=t8 run_measured_backend 1 -- --pull never i a
{ [ "$MB_STATUS" = 0 ] && [ "${MB_CLEANUP_OK}" = 1 ]; } && ok "tf: status preserved on clean teardown" || fail "status/cleanup on success"

# ---- cgroupfs unchanged + measure=0 ----
DRIVER=cgroupfs CGFS_PEAK=4096 run_measured_backend 1 -- --pull never i a
{ [ "$MB_STATUS" = 0 ] && [ "$MB_PEAK" = 4096 ] && [ "${MB_CLEANUP_OK}" = 1 ]; } && ok "cgroupfs unchanged" || fail "cgroupfs ($MB_STATUS/$MB_PEAK/$MB_CLEANUP_OK)"
DRIVER=systemd RUN_EXIT=0 run_measured_backend 0 -- --pull never i a
{ [ "$MB_STATUS" = 0 ] && [ -z "$MB_PEAK" ] && [ "${MB_CLEANUP_OK}" = 1 ]; } && ok "unmeasured path" || fail "unmeasured path"

echo
if [ "$fails" -eq 0 ]; then echo "docker firewall cgroup: ALL PASS"; exit 0
else echo "docker firewall cgroup: $fails FAILED"; exit 1; fi
