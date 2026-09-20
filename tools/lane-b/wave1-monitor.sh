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
#   agree    <url> <url> [<url>…]  do the validators report the same counts
#
# Exit codes: 0 ok, 1 a check failed, 2 usage.
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
    || { echo "FAIL: cannot scrape ${url%/}/metrics" >&2; exit 1; }
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

cmd_baseline() {
  local url=$1 text
  text=$(scrape "$url")
  cmd_verify "$url" >/dev/null || return 1
  echo "# baseline ${url} $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  local pair subsystem code
  for pair in $WAVE1; do
    subsystem=${pair%%:*}; code=${pair##*:}
    printf '%s %s %s\n' "$subsystem" "$code" "$(value_of "$subsystem" "$code" <<<"$text")"
  done
}

cmd_delta() {
  local url=$1 base=$2 text
  [[ -r $base ]] || { echo "FAIL: cannot read baseline $base" >&2; return 1; }
  text=$(scrape "$url")
  echo "subsystem   code  baseline  now       delta"
  local moved=0 subsystem code before now d
  while read -r subsystem code before; do
    [[ $subsystem == \#* || -z $subsystem ]] && continue
    now=$(value_of "$subsystem" "$code" <<<"$text")
    now=${now:-0}
    d=$(awk -v a="$now" -v b="$before" 'BEGIN{printf "%.0f", a-b}')
    printf '%-11s %-5s %-9s %-9s %s\n' "$subsystem" "$code" "$before" "$now" "$d"
    [[ $d -gt 0 ]] && moved=1
  done <"$base"
  echo
  if [[ $moved -eq 1 ]]; then
    echo "At least one subsystem started refusing. Sample one transaction with"
    echo "sum_getReceipt to see whether the refused sender had standing --"
    echo "the counter names the subsystem, not the legitimacy."
  else
    echo "Nothing moved. Before concluding 'no refused traffic', confirm the"
    echo "gate is actually open on this node:"
    echo "  curl -s -X POST ${url%/}/ -H 'content-type: application/json' \\"
    echo "    -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"chain_getActivationStatus\"}'"
    echo "and read gates[].active."
  fi
}

cmd_agree() {
  local urls=("$@") first="" bad=0
  [[ ${#urls[@]} -ge 2 ]] || { echo "FAIL: need at least two nodes" >&2; return 1; }
  local tmp; tmp=$(mktemp -d); trap 'rm -rf "$tmp"' RETURN
  local i=0 url
  for url in "${urls[@]}"; do
    scrape "$url" | samples | sort > "$tmp/$i"
    i=$((i + 1))
  done
  first="$tmp/0"
  for ((i = 1; i < ${#urls[@]}; i++)); do
    if ! diff -q "$first" "$tmp/$i" >/dev/null; then
      echo "DISAGREE: ${urls[0]} vs ${urls[$i]}"
      # `|| true`: diff exits 1 on a difference, which is the case this
      # branch exists for, and `set -e` would abort before the explanation.
      diff "$first" "$tmp/$i" | sed 's/^/    /' || true
      bad=1
    fi
  done
  if [[ $bad -eq 1 ]]; then
    echo
    echo "The validators are not reporting the same refusals. Two nodes"
    echo "executing the same blocks cannot disagree here. This is a"
    echo "mixed-binary or mixed-genesis condition and it is a fork in"
    echo "progress -- go to the abort rule in"
    echo "docs/operations/activation-rollout-evidence.md section 4."
    return 1
  fi
  echo "OK: ${#urls[@]} nodes report identical ${METRIC} series."
  echo "    (Counts can legitimately differ across a restart, because the"
  echo "     counter is per-process and not persisted. Compare nodes with"
  echo "     comparable uptime, or compare DELTAS over the same window.)"
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
