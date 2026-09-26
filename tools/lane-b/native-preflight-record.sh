#!/usr/bin/env bash
# native-preflight-record.sh --phase <before|stopped> --out <file> [options]
#
# Records, READ-ONLY, the facts a native (systemd) validator upgrade depends
# on. Run it ON the validator host, as the service's own user; no sudo. It
# never reads the validator key directory, never prints environment
# variables, never opens the database with RocksDB, and prints only the few
# configuration values it needs (health address, data_dir, whether bootnodes
# are set) -- config and genesis are otherwise recorded by hash.
# tools/lane-b/native-preflight.py decides from the records.
#
#   --unit <name>            systemd unit (default sumchain.service)
#   --rpc <host:port>        node RPC (default 127.0.0.1:8545)
#   --phase before           while the old binary runs
#   --phase stopped          after `systemctl stop`, before anything new starts:
#                            proves the process exited and the database lock is
#                            free, and hashes the rollback copy against the live
#                            data directory
#   --rollback-copy <dir>    the pre-upgrade copy of the data directory (stopped)
#   --rollback-binary <path> the preserved old executable (stopped)
#   --installed <path>       the new release binary, installed side by side
#
# Test hooks (never set in production): PREFLIGHT_PROC (default /proc).
set -euo pipefail
UNIT=sumchain.service RPC=127.0.0.1:8545 PHASE="" OUT="" COPY="" RBIN="" NEWBIN=""
while [[ $# -gt 0 ]]; do
  case $1 in
    --unit) UNIT=$2; shift 2 ;; --rpc) RPC=$2; shift 2 ;; --phase) PHASE=$2; shift 2 ;;
    --out) OUT=$2; shift 2 ;; --rollback-copy) COPY=$2; shift 2 ;; --rollback-binary) RBIN=$2; shift 2 ;;
    --installed) NEWBIN=$2; shift 2 ;;
    *) echo "usage: see the header of $0" >&2; exit 2 ;;
  esac
done
PROC=${PREFLIGHT_PROC:-/proc}
fail() { echo "PREFLIGHT RECORD FAIL: $*; no record written" >&2; exit 1; }
[[ $PHASE == before || $PHASE == stopped ]] || fail "--phase must be before or stopped"
[[ -n $OUT ]] || fail "--out is required"
for c in systemctl sha256sum stat df du awk python3; do command -v "$c" >/dev/null || fail "required command '$c' not found"; done
REC=$(mktemp); trap 'rm -f "$REC"' EXIT
put() { printf '%s: %s\n' "$1" "$2" >> "$REC"; }
h() { sha256sum "$1" | cut -d' ' -f1; }
rpc() { curl -fsS -m 5 -X POST "http://$RPC" -H 'content-type: application/json' \
          -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":${2:-[]}}" 2>/dev/null; }
prop() { systemctl show "$UNIT" -p "$1" --value; }

put phase "$PHASE"
put recorded_at "$(date -u +%FT%TZ)"
put unit "$UNIT"
put unit_active "$(systemctl is-active "$UNIT" 2>/dev/null || true)"
put unit_user "$(prop User)"
WD=$(prop WorkingDirectory); put unit_working_directory "$WD"
EXEC=$(prop ExecStart)
EXE=$(sed -nE 's/.*path=([^ ;]+).*/\1/p' <<<"$EXEC" | head -1)
[[ -n $EXE ]] || fail "cannot read ExecStart of $UNIT"
put executable "$EXE"
put kill_signal "$(prop KillSignal)"
put timeout_stop "$(prop TimeoutStopUSec)"
put restart_policy "$(prop Restart)"
put memory_max "$(prop MemoryMax)"
ARGV=$(sed -nE 's/.*argv\[\]=([^;]*);.*/\1/p' <<<"$EXEC" | head -1)
argval() { awk -v f="$1" '{for (i = 1; i < NF; i++) if ($i == f) {print $(i+1); exit}}' <<<"$ARGV"; }
abs() { case $1 in /*) echo "$1" ;; "") echo "" ;; *) echo "$WD/$1" ;; esac; }

[[ -f $EXE ]] || fail "executable $EXE does not exist"
put executable_sha256 "$(h "$EXE")"
put executable_owner "$(stat -c '%U:%G %a' "$EXE")"
put executable_mtime "$(stat -c '%y' "$EXE")"
v=$("$EXE" --version 2>/dev/null) || v=""
[[ $v =~ ^sumchain\ [0-9a-f]{40}$ ]] || v="none (pre-release binary; node_info $(rpc node_info | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"]["version"])' 2>/dev/null || echo unavailable))"
put executable_version "$v"
if git -C "$WD" rev-parse HEAD >/dev/null 2>&1; then put source_checkout_commit "$(git -C "$WD" rev-parse HEAD)"; else put source_checkout_commit none; fi

CONF=$(abs "$(argval --config)")
[[ -f $CONF ]] || fail "the unit's --config file does not exist"
put config_sha256 "$(h "$CONF")"
section_key() {  # section, key -> value (quotes stripped), from the TOML config
  awk -v s="[$1]" -v k="$2" '
    /^[[:space:]]*\[/ {cur = $0; gsub(/[[:space:]]/, "", cur)}
    cur == s && $0 ~ "^[[:space:]]*" k "[[:space:]]*=" {sub(/^[^=]*=[[:space:]]*/, ""); gsub(/"/, ""); sub(/[[:space:]]*(#.*)?$/, ""); print; exit}' "$CONF"
}
GEN=$(abs "$(argval --genesis)"); [[ -n $(argval --genesis) ]] || GEN=$(abs "$(section_key node genesis)")
[[ -f $GEN ]] || fail "the genesis file does not exist"
put genesis_sha256 "$(h "$GEN")"
HEALTH=$(section_key health addr); put health_addr "${HEALTH:-absent}"
DATA=$(abs "$(section_key node data_dir)")
[[ -d $DATA ]] || fail "data_dir does not exist"
put data_dir "$DATA"
put data_bytes "$(du -sb "$DATA" | cut -f1)"
put data_fs "$(df -PT "$DATA" | awk 'NR==2 {print $2, $7}')"
put disk_available_bytes "$(df -PB1 "$DATA" | awk 'NR==2 {print $4}')"

# Memory: what is installed (lsmem, online memory blocks) and what the kernel
# makes available after its own reservations (MemTotal) are different numbers.
put mem_total_bytes "$(awk '/^MemTotal:/ {print $2 * 1024}' "$PROC/meminfo")"
put mem_available_bytes "$(awk '/^MemAvailable:/ {print $2 * 1024}' "$PROC/meminfo")"
online=$(lsmem -b --summary=only 2>/dev/null | awk -F: '/Total online memory/ {gsub(/[^0-9]/, "", $2); print $2}') || online=""
put mem_installed_online_bytes "${online:-unavailable}"

# Topology, from configuration and observable connections only.
BOOT=$(argval --bootnodes); [[ -n $BOOT ]] || BOOT=$(section_key network bootnodes | tr -d '[] ')
put bootnodes_configured "$([[ -n $BOOT ]] && echo yes || echo no)"

if [[ $PHASE == before ]]; then
  PID=$(prop MainPID)
  [[ $PID =~ ^[0-9]+$ && $PID -gt 0 ]] || fail "$UNIT has no main process"
  put running_image_sha256 "$(h "$PROC/$PID/exe" 2>/dev/null || echo unreadable)"
  put node_rss_bytes "$(awk '/^VmRSS:/ {print $2 * 1024}' "$PROC/$PID/status" 2>/dev/null || echo unavailable)"
  put memory_current "$(prop MemoryCurrent)"
  stats=$(rpc get_p2p_stats) || stats=""
  put p2p_outbound "$(python3 -c 'import json,sys; print(json.load(sys.stdin)["result"]["outbound_connections"])' <<<"$stats" 2>/dev/null || echo unavailable)"
  put p2p_inbound "$(python3 -c 'import json,sys; print(json.load(sys.stdin)["result"]["inbound_connections"])' <<<"$stats" 2>/dev/null || echo unavailable)"
  H=$(journalctl -u "$UNIT" --no-pager -n 20000 2>/dev/null | grep -oE 'Produced block 0x[0-9a-f]+ at height [0-9]+' | tail -1 | awk '{print $NF}') || H=""
  if [[ -n $H ]]; then
    p=$(rpc get_block_by_height "[$H]" | grep -oE '"proposer":"[0-9a-f]{64}"' | cut -d'"' -f4) || p=""
    put validator_pubkey "${p:-unavailable}"
  else
    put validator_pubkey unavailable
  fi
  put chain_height "$(rpc node_info | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"]["current_height"])' 2>/dev/null || echo unavailable)"
else
  pgrep -f "^$EXE( |$)" >/dev/null && put process_exited no || put process_exited yes
  # RocksDB holds an fcntl lock on <data>/LOCK while open. Taking it here,
  # non-blocking, and releasing it at once proves nothing holds the database;
  # it never opens the database itself.
  lock=$(python3 - "$DATA/LOCK" <<'PY'
import errno, fcntl, os, sys
try:
    fd = os.open(sys.argv[1], os.O_RDWR)
except FileNotFoundError:
    print("absent"); sys.exit()
try:
    fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    fcntl.lockf(fd, fcntl.LOCK_UN)
    print("free")
except OSError as e:
    print("held" if e.errno in (errno.EAGAIN, errno.EACCES) else f"error {e.errno}")
PY
)
  put db_lock "$lock"
  tree() {  # sha256 over (relative path, size, sha256) of every file, sorted
    (cd "$1" && find . -type f ! -name LOCK -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1)
  }
  put data_tree_sha256 "$(tree "$DATA")"
  if [[ -n $COPY ]]; then
    [[ -d $COPY ]] || fail "--rollback-copy $COPY is not a directory"
    put rollback_copy "$COPY"
    put rollback_copy_tree_sha256 "$(tree "$COPY")"
    put rollback_copy_bytes "$(du -sb "$COPY" | cut -f1)"
    put rollback_copy_same_fs "$([[ $(df -P "$COPY" | awk 'NR==2 {print $1}') == $(df -P "$DATA" | awk 'NR==2 {print $1}') ]] && echo yes || echo no)"
  fi
  put disk_available_after_copy_bytes "$(df -PB1 "$DATA" | awk 'NR==2 {print $4}')"
  if [[ -n $RBIN ]]; then
    [[ -f $RBIN && ! -L $RBIN ]] || fail "--rollback-binary $RBIN is not a regular file"
    put rollback_binary "$RBIN"
    put rollback_binary_sha256 "$(h "$RBIN")"
  fi
fi
if [[ -n $NEWBIN ]]; then
  [[ -f $NEWBIN ]] || fail "--installed $NEWBIN does not exist"
  put installed_binary "$NEWBIN"
  put installed_binary_sha256 "$(h "$NEWBIN")"
  put installed_binary_version "$("$NEWBIN" --version 2>/dev/null || echo none)"
fi
put machine "$(uname -m)"
mv "$REC" "$OUT"; trap - EXIT
echo "recorded $OUT" >&2
