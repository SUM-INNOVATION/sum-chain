#!/usr/bin/env bash
# Battery for wave1-monitor.sh's restart handling. Every case is a /metrics
# fixture served over file:// (curl reads it natively, so no server), with the
# wall clock driven through WAVE1_NOW. Each case states what the monitor must
# say; the ones marked OLD-WRONG also record what the pre-repair script said,
# so the battery documents the defect as well as the fix.
#
#   bash tools/lane-b/wave1-monitor-test.sh            # the script in this tree
#   MONITOR=/path/to/old.sh bash tools/lane-b/wave1-monitor-test.sh
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
MON=${MONITOR:-$HERE/wave1-monitor.sh}
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
fail=0; n=0

# mk <dir> <uptime> <height> <healthcare-count>  (every other series 0)
mk() {
  mkdir -p "$1"
  {
    echo "# TYPE sumchain_tx_execution_errors_total counter"
    for p in nft:2 docclass:8 tax:9 agreement:11 legal:12 property:13 healthcare:14 employment:15 finance:16; do
      s=${p%%:*}; c=${p##*:}; v=0; [[ $s == healthcare ]] && v=$4
      echo "sumchain_tx_execution_errors_total{subsystem=\"$s\",code=\"$c\"} $v"
    done
    echo "sumchain_uptime_seconds $2"
    echo "sumchain_block_height $3"
  } >"$1/metrics"
}
url() { echo "file://$1"; }

# expect <name> <want-exit> <want-text> -- <command...>
expect() {
  local name=$1 want=$2 text=$3; shift 4
  n=$((n+1))
  local out rc; out=$("$@" 2>&1); rc=$?
  if [[ $rc -eq $want ]] && grep -q -- "$text" <<<"$out"; then
    printf '  ok    %-58s exit %s\n' "$name" "$rc"
  else
    printf '  FAIL  %-58s exit %s (want %s, text "%s")\n' "$name" "$rc" "$want" "$text"
    sed 's/^/          | /' <<<"$out" | tail -4; fail=$((fail+1))
  fi
}

# ---- delta ------------------------------------------------------------------
# The node has run 1000s at baseline (t=10000, so it started at t=9000).
mk "$T/a" 1000 500 0
WAVE1_NOW=10000 bash "$MON" baseline "$(url "$T/a")" >"$T/a.base"

mk "$T/a" 1600 700 4                      # same process, 600s later, 4 refusals
expect "delta: no restart, refusals seen" 0 "started refusing" -- \
  env WAVE1_NOW=10600 bash "$MON" delta "$(url "$T/a")" "$T/a.base"

mk "$T/a" 1600 700 0                      # same process, nothing refused
expect "delta: no restart, nothing refused" 0 "Nothing moved, over a window with no restart" -- \
  env WAVE1_NOW=10600 bash "$MON" delta "$(url "$T/a")" "$T/a.base"

# OLD-WRONG: baseline 100 refusals; restart; 3 real refusals since. Old: delta
# -97, "Nothing moved", exit 0 -- the three refusals vanish.
mk "$T/b" 1000 500 100
WAVE1_NOW=10000 bash "$MON" baseline "$(url "$T/b")" >"$T/b.base"
mk "$T/b" 60 700 3
expect "delta: restart, count FELL (was hidden as 'nothing moved')" 3 "INCONCLUSIVE" -- \
  env WAVE1_NOW=10600 bash "$MON" delta "$(url "$T/b")" "$T/b.base"

# The coincidence a fell-below check alone misses: baseline 3; restart; exactly
# 3 since, so every delta is 0. Only the start time can see it.
mk "$T/c" 1000 500 3
WAVE1_NOW=10000 bash "$MON" baseline "$(url "$T/c")" >"$T/c.base"
mk "$T/c" 60 700 3
expect "delta: restart, count back EXACTLY to baseline (delta 0)" 3 "process restarted" -- \
  env WAVE1_NOW=10600 bash "$MON" delta "$(url "$T/c")" "$T/c.base"

# Why uptimes cannot simply be compared: baseline at uptime 10; restart 5s
# later; 100s after that uptime is 100 > 10 and looks continuous.
mk "$T/d" 10 500 0
WAVE1_NOW=10000 bash "$MON" baseline "$(url "$T/d")" >"$T/d.base"
mk "$T/d" 100 540 0
expect "delta: restart that uptime alone would miss" 3 "process restarted" -- \
  env WAVE1_NOW=10105 bash "$MON" delta "$(url "$T/d")" "$T/d.base"

# A baseline written by the old script carries no epoch/uptime/height.
printf '# baseline x 2026-01-01T00:00:00Z\nhealthcare 14 0\n' >"$T/old.base"
mk "$T/e" 1600 700 0
expect "delta: pre-repair baseline refuses to measure" 3 "predates restart detection" -- \
  env WAVE1_NOW=10600 bash "$MON" delta "$(url "$T/e")" "$T/old.base"

# ---- agree ------------------------------------------------------------------
# Two healthy validators that STARTED AT DIFFERENT TIMES: raw totals 50 vs 9,
# but over the same blocks each refused 2. OLD-WRONG: "fork in progress".
mk "$T/v1" 1000 500 50; WAVE1_NOW=10000 bash "$MON" baseline "$(url "$T/v1")" >"$T/v1.base"
mk "$T/v2" 200  500 9;  WAVE1_NOW=10000 bash "$MON" baseline "$(url "$T/v2")" >"$T/v2.base"
mk "$T/v1" 1600 700 52; mk "$T/v2" 800 700 11
expect "agree: different uptimes, same blocks, same deltas" 0 "OK: 2 nodes" -- \
  env WAVE1_NOW=10600 bash "$MON" agree "$T/v1.base" "$T/v2.base"

mk "$T/v2" 800 700 12                     # same blocks, one more refusal on v2
expect "agree: same blocks, different refusals = fork" 1 "DISAGREE" -- \
  env WAVE1_NOW=10600 bash "$MON" agree "$T/v1.base" "$T/v2.base"

mk "$T/v2" 30 700 0                       # v2 restarted inside the window
expect "agree: one node restarted -> not a fork" 3 "Nothing is compared" -- \
  env WAVE1_NOW=10600 bash "$MON" agree "$T/v1.base" "$T/v2.base"

mk "$T/v2" 800 701 11                     # v2 one block ahead
expect "agree: nodes a block apart -> not a fork" 3 "cover different blocks" -- \
  env WAVE1_NOW=10600 bash "$MON" agree "$T/v1.base" "$T/v2.base"

echo
if [[ $fail -eq 0 ]]; then echo "WAVE1 MONITOR BATTERY OK: $n cases"; exit 0; fi
echo "WAVE1 MONITOR BATTERY FAILED: $fail of $n"; exit 1
