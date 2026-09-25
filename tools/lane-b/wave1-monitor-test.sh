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

# ---- verify -----------------------------------------------------------------
# The gate to Stage 1 being complete. Every way the telemetry can be absent
# must fail it, and none may read as "present, nothing refused".
mk "$T/ok" 100 10 0
expect "verify: all nine subsystems, two labels" 0 "all nine Wave 1 subsystems" -- \
  bash "$MON" verify "$(url "$T/ok")"

expect "verify: no /metrics at all (a 404 or no listener)" 4 "MISSING DATA: cannot scrape" -- \
  bash "$MON" verify "file://$T/no-such-node"

mkdir -p "$T/nofam"; printf 'sumchain_uptime_seconds 100\nsumchain_block_height 10\n' >"$T/nofam/metrics"
expect "verify: the counter family absent" 1 "is not exposed" -- \
  bash "$MON" verify "$(url "$T/nofam")"

mkdir -p "$T/typeonly"; echo "# TYPE sumchain_tx_execution_errors_total counter" >"$T/typeonly/metrics"
expect "verify: family typed but no samples" 1 "emits no samples" -- \
  bash "$MON" verify "$(url "$T/typeonly")"

mk "$T/eight" 100 10 0; grep -v 'subsystem="finance"' "$T/eight/metrics" >"$T/eight/x" && mv "$T/eight/x" "$T/eight/metrics"
expect "verify: one Wave 1 subsystem absent" 1 "no series for finance/16" -- \
  bash "$MON" verify "$(url "$T/eight")"

mk "$T/three" 100 10 0
sed 's/code="9"}/code="9",sender="abc"}/' "$T/three/metrics" >"$T/three/x" && mv "$T/three/x" "$T/three/metrics"
expect "verify: a third label (unbounded cardinality)" 1 "other than two labels" -- \
  bash "$MON" verify "$(url "$T/three")"

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

# ---- missing data is not zero change, and is not a fork ----------------------
# drop <dir> <subsystem>: remove one series from a fixture, as a node that
# stopped exporting it would.
drop() { grep -v "subsystem=\"$2\"" "$1/metrics" >"$1/m.tmp" && mv "$1/m.tmp" "$1/metrics"; }

mk "$T/m" 1000 500 0
WAVE1_NOW=10000 bash "$MON" baseline "$(url "$T/m")" >"$T/m.base"
mk "$T/m" 1600 700 0; drop "$T/m" healthcare
expect "delta: a series absent now -> MISSING, not 'nothing moved'" 4 "MISSING DATA" -- \
  env WAVE1_NOW=10600 bash "$MON" delta "$(url "$T/m")" "$T/m.base"

expect "delta: endpoint unreachable -> MISSING" 4 "MISSING DATA: cannot scrape" -- \
  env WAVE1_NOW=10600 bash "$MON" delta "file://$T/does-not-exist" "$T/m.base"

mk "$T/g" 1600 700 0; grep -v '^sumchain_uptime_seconds' "$T/g/metrics" >"$T/g/x" && mv "$T/g/x" "$T/g/metrics"
expect "delta: uptime gauge absent -> MISSING" 4 "MISSING DATA" -- \
  env WAVE1_NOW=10600 bash "$MON" delta "$(url "$T/g")" "$T/m.base"

# agree: exit 1 there means DISAGREE = HALT, so missing data must never reach it.
mk "$T/v1" 1000 500 50; WAVE1_NOW=10000 bash "$MON" baseline "$(url "$T/v1")" >"$T/v1.base"
mk "$T/v2" 200  500 9;  WAVE1_NOW=10000 bash "$MON" baseline "$(url "$T/v2")" >"$T/v2.base"
mk "$T/v1" 1600 700 52; mk "$T/v2" 800 700 11; drop "$T/v2" healthcare
expect "agree: a series absent on one node -> MISSING, never DISAGREE" 4 "Absent data is not a disagreement" -- \
  env WAVE1_NOW=10600 bash "$MON" agree "$T/v1.base" "$T/v2.base"

mk "$T/v2" 800 700 11; rm -rf "$T/v2"
expect "agree: one endpoint unreachable -> MISSING, never DISAGREE" 4 "MISSING DATA: cannot scrape" -- \
  env WAVE1_NOW=10600 bash "$MON" agree "$T/v1.base" "$T/v2.base"

echo
if [[ $fail -eq 0 ]]; then echo "WAVE1 MONITOR BATTERY OK: $n cases"; exit 0; fi
echo "WAVE1 MONITOR BATTERY FAILED: $fail of $n"; exit 1
