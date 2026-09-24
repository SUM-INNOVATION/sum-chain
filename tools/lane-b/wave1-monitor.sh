#!/usr/bin/env bash
# Wave 1 activation monitoring: the thing an operator actually runs.
#
# Four subcommands, all against a node's /metrics endpoint. No Prometheus
# required -- a node's own exposition is enough to answer every question in
# the first hour, and requiring a working Prometheus before you can tell
# whether the gate fired is the wrong dependency to have at that moment.
#
#   verify   <url>                 the binary carries the telemetry, correctly shaped
#   baseline <url>                 the nine Wave 1 series, before the height
#   delta    <url> <baseline-file> what has moved since the baseline
#   agree    <baseline> <baseline> [<baseline>…]
#                                  do the validators refuse the same things over
#                                  the same blocks (each baseline names its url)
#
# Exit codes: 0 ok, 1 a check failed, 2 usage, 3 INCONCLUSIVE -- the window
# cannot be measured (a node restarted inside it, or the nodes' windows cover
# different blocks). 3 is never success and never a fork: it means "measure
# again", and a script must not collapse it into either.
# 4 MISSING DATA -- an endpoint could not be scraped, or a series or gauge the
# measurement needs is absent. Absent data is not zero change and not a fork:
# a validator whose metrics port is down must never read as "nothing moved",
# and must never read as DISAGREE (exit 1), which the rollout treats as HALT.
#
# THE COUNTER IS PER-PROCESS. It lives in a static array and starts at zero
# every time the node starts; nothing persists it. So a raw total means
# "refusals since this process started", which differs between two healthy
# validators whenever they started at different times, and resets under any
# single one of them on restart. Every comparison here is therefore a DELTA
# over a window, and every window is first checked for a restart.
#
# See docs/operations/wave1-activation-monitoring.md.

set -euo pipefail

METRIC=sumchain_tx_execution_errors_total

# The nine Wave 1 subsystems and the status code each refuses under. Kept in
# step with crates/primitives/src/tx_error_metrics.rs and demonstrated by
# crates/state/tests/wave1_execution_error_signal.rs.
WAVE1='nft:2 docclass:8 tax:9 agreement:11 legal:12 property:13 healthcare:14 employment:15 finance:16'

usage() {
  sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'
  exit 2
}

scrape() {
  local url=$1
  curl -fsS --max-time 10 "${url%/}/metrics" \
    || { echo "MISSING DATA: cannot scrape ${url%/}/metrics" >&2; exit 4; }
}

# Every sample line of the counter family, "subsystem code value".
samples() {
  grep "^${METRIC}{" \
    | sed -E 's/^.*subsystem="([^"]*)",code="([^"]*)"\} ([0-9.e+]+).*$/\1 \2 \3/'
}

# One series' value, or the empty string when there is no such series.
#
# `samples` and awk rather than a grep whose pattern ends in `}`: BSD grep
# parses `{...}` in a basic regular expression as an interval and matches
# nothing, silently, which is how this script first reported every baseline as
# blank.
value_of() {
  local subsystem=$1 code=$2
  samples | awk -v s="$subsystem" -v c="$code" '$1==s && $2==c {print $3; found=1} END{if(!found) print ""}'
}

cmd_verify() {
  local url=$1 text
  text=$(scrape "$url")

  if ! grep -q "^# TYPE ${METRIC} counter$" <<<"$text"; then
    echo "MISSING: ${METRIC} is not exposed by ${url}."
    echo "         This binary predates the failed-receipt telemetry."
    echo "         STAGE 1 IS NOT COMPLETE. Do not set any activation height."
    return 1
  fi

  local lines bad=0
  lines=$(samples <<<"$text" | wc -l | tr -d ' ')
  if [[ "$lines" -eq 0 ]]; then
    echo "MISSING: ${METRIC} declares its type but emits no samples."
    return 1
  fi

  # Exactly two labels on every sample, named and ordered. A third label is a
  # cardinality multiplier; see the module comment in tx_error_metrics.rs.
  while IFS= read -r line; do
    local inside
    inside=${line#*\{}; inside=${inside%%\}*}
    if [[ $(tr -cd ',' <<<"$inside" | wc -c) -ne 1 ]]; then
      echo "FAIL: sample carries other than two labels: $line"; bad=1
    fi
    [[ $inside == subsystem=\"*\",code=\"*\" ]] \
      || { echo "FAIL: labels are not subsystem,code: $line"; bad=1; }
  done < <(grep "^${METRIC}{" <<<"$text")

  # Every Wave 1 subsystem has a series, or the activation has a blind spot.
  local pair subsystem code
  for pair in $WAVE1; do
    subsystem=${pair%%:*}; code=${pair##*:}
    [[ -n "$(value_of "$subsystem" "$code" <<<"$text")" ]] \
      || { echo "FAIL: no series for ${subsystem}/${code}"; bad=1; }
  done

  [[ $bad -eq 0 ]] || return 1
  echo "OK: ${METRIC} present at ${url}, ${lines} series, two bounded labels,"
  echo "    all nine Wave 1 subsystems represented."
}

# Seconds within which two estimates of the process start time are treated as
# the same start. Uptime is whole seconds and each scrape takes time, so two
# readings of an unchanged process can disagree by a second or two. A real
# restart moves the start time by at least the downtime.
RESTART_TOLERANCE=${WAVE1_RESTART_TOLERANCE:-3}

# Wall-clock seconds. Overridable ONLY so the test battery can drive time.
now_epoch() { echo "${WAVE1_NOW:-$(date +%s)}"; }

# A plain gauge from the exposition, e.g. `sumchain_uptime_seconds 12345`.
gauge() { awk -v n="$1" '$1==n {print $2; exit}'; }

# A `# key value` header line of a baseline file.
hdr() { awk -v k="$2" '$1=="#" && $2==k {print $3; exit}' "$1"; }

cmd_baseline() {
  local url=$1 text up h
  text=$(scrape "$url")
  cmd_verify "$url" >/dev/null || return 1
  up=$(gauge sumchain_uptime_seconds <<<"$text")
  h=$(gauge sumchain_block_height <<<"$text")
  [[ -n $up && -n $h ]] || {
    echo "FAIL: ${url} exposes no sumchain_uptime_seconds or sumchain_block_height;" >&2
    echo "      without them a restart inside the window cannot be detected." >&2
    return 1; }
  echo "# baseline ${url} $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "# url ${url}"
  echo "# epoch $(now_epoch)"
  echo "# uptime ${up}"
  echo "# height ${h}"
  local pair subsystem code
  for pair in $WAVE1; do
    subsystem=${pair%%:*}; code=${pair##*:}
    printf '%s %s %s\n' "$subsystem" "$code" "$(value_of "$subsystem" "$code" <<<"$text")"
  done
}

# Measure one node against its baseline. Writes into directory $3:
#   reset   empty, or the reason the window is unmeasurable
#   range   "<height at baseline> <height now>"
#   deltas  "subsystem code before now delta", one line per Wave 1 series
#
# A reset is detected two independent ways, because either alone has a hole:
#   * the PROCESS START TIME (wall clock minus uptime) moved forward. Comparing
#     uptimes directly is not enough -- baseline at uptime 10s, restart 5s
#     later, and uptime passes 10 again soon after, looking continuous.
#   * any series went DOWN. A counter that only increments can only fall by
#     being reset.
# The residual case neither catches is a restart faster than the tolerance in
# which, by coincidence, every series has since climbed back to at least its
# baseline. That needs a sub-${RESTART_TOLERANCE}s node restart; it is stated
# here rather than hidden.
measure() {
  local url=$1 base=$2 out=$3 text b_ep b_up b_h n_ep n_up n_h
  [[ -r $base ]] || { echo "FAIL: cannot read baseline $base" >&2; return 1; }
  b_ep=$(hdr "$base" epoch); b_up=$(hdr "$base" uptime); b_h=$(hdr "$base" height)
  : >"$out/reset"
  if [[ -z $b_ep || -z $b_up || -z $b_h ]]; then
    echo "baseline $base predates restart detection (no epoch/uptime/height); take a new one" >"$out/reset"
  fi
  # Handled explicitly: callers invoke measure from an `||` list, and bash
  # disables `set -e` inside such a call, so a failed scrape would otherwise
  # continue with empty text and surface as some unrelated failure.
  text=$(scrape "$url") || return 4
  n_ep=$(now_epoch)
  n_up=$(gauge sumchain_uptime_seconds <<<"$text")
  n_h=$(gauge sumchain_block_height <<<"$text")
  [[ -n $n_up && -n $n_h ]] || {
    echo "MISSING DATA: ${url} exposes no sumchain_uptime_seconds or sumchain_block_height" >&2
    return 4; }
  echo "${b_h:-?} ${n_h}" >"$out/range"
  if [[ ! -s $out/reset ]]; then
    local b_start=$((b_ep - b_up)) n_start=$((n_ep - n_up))
    if (( n_start - b_start > RESTART_TOLERANCE )); then
      echo "the process restarted: its start time moved from ${b_start} to ${n_start}" >"$out/reset"
    fi
  fi
  : >"$out/deltas"; : >"$out/missing"
  local subsystem code before now d
  while read -r subsystem code before; do
    [[ $subsystem == \#* || -z $subsystem ]] && continue
    now=$(value_of "$subsystem" "$code" <<<"$text")
    # An absent series is NOT a zero. It used to be defaulted to 0 here, which
    # made a node that stopped exporting a subsystem read as "nothing moved".
    if [[ -z $now || -z $before ]]; then
      echo "${subsystem}/${code} absent $([[ -z $before ]] && echo 'from the baseline' || echo 'from the node now')" >>"$out/missing"
      echo "$subsystem $code ${before:--} ${now:--} missing" >>"$out/deltas"
      continue
    fi
    d=$(awk -v a="$now" -v b="$before" 'BEGIN{printf "%.0f", a-b}')
    echo "$subsystem $code $before $now $d" >>"$out/deltas"
    if (( d < 0 )) && [[ ! -s $out/reset ]]; then
      echo "${subsystem}/${code} fell from ${before} to ${now}, which only a reset can do" >"$out/reset"
    fi
  done <"$base"
}

cmd_delta() {
  local url=$1 base=$2 m rc=0; m=$(mktemp -d); trap 'rm -rf "$m"' RETURN
  measure "$url" "$base" "$m" || rc=$?
  (( rc == 0 )) || return "$rc"
  echo "subsystem   code  baseline  now       delta"
  local moved=0 subsystem code before now d
  while read -r subsystem code before now d; do
    printf '%-11s %-5s %-9s %-9s %s\n' "$subsystem" "$code" "$before" "$now" "$d"
    if [[ $d != missing ]] && (( d > 0 )); then moved=1; fi
  done <"$m/deltas"
  echo "blocks: $(cat "$m/range")"
  echo
  if [[ -s $m/missing ]]; then
    echo "MISSING DATA:"; sed 's/^/  /' "$m/missing"
    echo "An absent series is not a series that did not move. Nothing here says"
    echo "whether anything was refused. Check that the node exports all nine Wave 1"
    echo "series (\`verify\`) and that the baseline was taken by this script."
    return 4
  fi
  # A reset is checked next and wins over any delta. Before this, a restart zeroed the counter,
  # every delta went negative, and the script printed "Nothing moved" -- hiding
  # every refusal since the restart, which is the unsafe direction.
  if [[ -s $m/reset ]]; then
    echo "INCONCLUSIVE: $(cat "$m/reset")."
    echo "The counter began again at zero, so no delta over this window means"
    echo "anything -- in particular it does NOT mean nothing was refused. Take a"
    echo "new baseline and observe a fresh window."
    return 3
  fi
  if [[ $moved -eq 1 ]]; then
    echo "At least one subsystem started refusing. Sample one transaction with"
    echo "sum_getReceipt to see whether the refused sender had standing --"
    echo "the counter names the subsystem, not the legitimacy."
  else
    echo "Nothing moved, over a window with no restart. Before concluding 'no"
    echo "refused traffic', confirm the gate is actually open on this node:"
    echo "  curl -s -X POST ${url%/}/ -H 'content-type: application/json' \\"
    echo "    -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"chain_getActivationStatus\"}'"
    echo "and read gates[].active."
  fi
}

cmd_agree() {
  [[ $# -ge 2 ]] || { echo "FAIL: need at least two baselines" >&2; return 2; }
  local tmp; tmp=$(mktemp -d); trap 'rm -rf "$tmp"' RETURN
  local i=0 base url incon=0 rc
  for base in "$@"; do
    url=$(hdr "$base" url)
    [[ -n $url ]] || { echo "FAIL: $base names no url; take it with this version's baseline" >&2; return 1; }
    mkdir -p "$tmp/$i"
    rc=0; measure "$url" "$base" "$tmp/$i" || rc=$?
    (( rc == 0 )) || { echo "not compared: ${url} (exit ${rc})"; return "$rc"; }
    if [[ -s $tmp/$i/missing ]]; then
      echo "MISSING DATA on ${url}:"; sed 's/^/  /' "$tmp/$i/missing"
      echo "Nothing is compared. Absent data is not a disagreement."
      return 4
    fi
    echo "$url" >"$tmp/$i/url"
    cut -d' ' -f1,2,5 "$tmp/$i/deltas" | sort >"$tmp/$i/cmp"
    if [[ -s $tmp/$i/reset ]]; then
      echo "INCONCLUSIVE: ${url}: $(cat "$tmp/$i/reset")"; incon=1
    fi
    i=$((i + 1))
  done
  # A restart anywhere makes that node's window unmeasurable, so comparing it
  # would be comparing a reset counter with a live one -- which is exactly the
  # false "fork in progress" the old raw-total comparison raised on every
  # restart.
  if [[ $incon -eq 1 ]]; then
    echo "At least one node restarted inside its window. Nothing is compared."
    echo "Re-baseline every node and observe a fresh window."
    return 3
  fi
  local n=$i same_range=1 same_delta=1
  for ((i = 1; i < n; i++)); do
    diff -q "$tmp/0/range" "$tmp/$i/range" >/dev/null || same_range=0
    diff -q "$tmp/0/cmp" "$tmp/$i/cmp" >/dev/null || same_delta=0
  done
  for ((i = 0; i < n; i++)); do
    echo "  $(cat "$tmp/$i/url")  blocks $(cat "$tmp/$i/range")"
  done
  if [[ $same_range -eq 1 && $same_delta -eq 1 ]]; then
    echo "OK: ${n} nodes, same blocks, no restart, identical refusal deltas."
    return 0
  fi
  if [[ $same_range -eq 1 ]]; then
    # The ONLY case that is a fork signal: the same blocks, no restart on any
    # node, and different refusals. Two nodes executing the same blocks under
    # the same rules cannot disagree here.
    echo "DISAGREE: the same blocks produced different refusals:"
    for ((i = 1; i < n; i++)); do
      diff "$tmp/0/cmp" "$tmp/$i/cmp" | sed 's/^/    /' || true
    done
    echo
    echo "This is a mixed-binary or mixed-genesis condition and a fork in"
    echo "progress -- go to the abort rule in"
    echo "docs/operations/activation-rollout-evidence.md section 4."
    return 1
  fi
  echo "INCONCLUSIVE: the nodes' windows cover different blocks, so their deltas"
  echo "are not comparable -- one node can be a block ahead of another without"
  echo "anything being wrong. Take every baseline at the same height, and run"
  echo "agree when every node reports the same height again."
  return 3
}

[[ $# -ge 1 ]] || usage
sub=$1; shift
case "$sub" in
  verify)   [[ $# -eq 1 ]] || usage; cmd_verify "$1" ;;
  baseline) [[ $# -eq 1 ]] || usage; cmd_baseline "$1" ;;
  delta)    [[ $# -eq 2 ]] || usage; cmd_delta "$1" "$2" ;;
  agree)    cmd_agree "$@" ;;
  *)        usage ;;
esac
