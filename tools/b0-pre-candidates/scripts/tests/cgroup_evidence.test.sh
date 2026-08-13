#!/usr/bin/env bash
# Independent-parser tests for the cgroup validation evidence encoder (emit_cgroup_evidence.py). Every
# emitted line is parsed back with a real JSON parser (python json.loads) and asserted field-by-field.
# Covers: clean PASS with empty detail/stderr; cleanup failure with nonempty stderr; quotes /
# backslashes / newline / CR / tab / other control chars; numeric+boolean type preservation; exactly
# one complete JSON object per JSONL line; and NO partial output after an encoder failure.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
EMIT="$HERE/../emit_cgroup_evidence.py"
fails=0
ok()   { printf 'ok    %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1"; fails=$((fails+1)); }
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

[ -f "$EMIT" ] || { echo "FAIL  emitter not found: $EMIT"; exit 1; }
# in-memory compile (no bytecode file / __pycache__ left behind)
python3 -c 'import sys; compile(open(sys.argv[1]).read(), sys.argv[1], "exec")' "$EMIT" && ok "emitter compiles" || fail "emitter compile"

# args template (18 fields after the evidence path): result detail driver image_ref image_id os arch
# repo_digests immutability container_cmd run_cmd resolved_cgroup peak status cleanup_ok argv rc stderr
run_ok() { python3 "$EMIT" "$@"; }  # prints the JSON line, appends to arg1 if non-empty

# ---- clean PASS: empty detail + empty teardown_stderr decode to "" (not null/missing); types ----
line="$(run_ok "$WORK/ev.jsonl" pass "" systemd "busybox@sha256:aa" "sha256:bb" linux amd64 "" digest-ref "sh -c x" "docker run" "systemd:cell=/d" 71364608 0 1 "/usr/bin/sudo -n /usr/bin/systemctl stop -- b0-final-proving-cellz.slice" 0 "")"
python3 - "$line" <<'PY' && ok "clean PASS: empty detail/stderr == \"\"; types correct" || exit 1
import json,sys
d=json.loads(sys.argv[1])
assert d["result"]=="pass"
assert d["detail"]=="" and isinstance(d["detail"],str)
assert d["teardown_stderr"]=="" and isinstance(d["teardown_stderr"],str)
assert isinstance(d["memory_peak_bytes"],int) and d["memory_peak_bytes"]==71364608
assert isinstance(d["workload_exit_status"],int) and d["workload_exit_status"]==0
assert d["cleanup_ok"] is True
assert isinstance(d["teardown_rc"],int) and d["teardown_rc"]==0
assert d["driver"]=="systemd" and d["platform"]=="linux/amd64" and d["pull"]=="never"
assert "b0-final-proving-cellz.slice" in d["teardown_argv"]
PY
[ "$(wc -l <"$WORK/ev.jsonl" | tr -d ' ')" = 1 ] && ok "clean PASS: exactly one line written" || fail "line count"

# ---- cleanup failure: nonempty stderr round-trips; cleanup_ok=false; status retained ----
line="$(run_ok "" cleanup_fail "per-cell cgroup dir remains after stop: /x" systemd img id linux amd64 "" tag c r cg 4096 0 0 "argv" 1 "sudo: a password is required")"
python3 - "$line" <<'PY' && ok "cleanup failure: nonempty stderr + boolean false + status retained" || exit 1
import json,sys
d=json.loads(sys.argv[1])
assert d["result"]=="cleanup_fail"
assert d["detail"]=="per-cell cgroup dir remains after stop: /x"
assert d["teardown_stderr"]=="sudo: a password is required"
assert d["cleanup_ok"] is False
assert d["workload_exit_status"]==0
assert d["teardown_rc"]==1
PY

# ---- quotes / backslashes / newline / CR / tab / control char round-trip ----
python3 - "$EMIT" <<'PY' && ok "control chars round-trip (quote, backslash, nl, cr, tab, \\x01)" || fail "control chars"
import json,subprocess,sys
emit=sys.argv[1]
s='a"b\\c\nd\re\tf\x01g'
r=subprocess.run(["python3",emit,"","fail",s,"systemd","i","id","linux","amd64","","tag","cc","rc","cg","0","1","0","argv","0",s],capture_output=True,text=True)
assert r.returncode==0, r.stderr
d=json.loads(r.stdout)
assert d["detail"]==s and d["teardown_stderr"]==s, "roundtrip mismatch"
# the RAW emitted line must not contain a literal newline/CR/tab inside the JSON (they must be escaped)
raw=r.stdout.rstrip("\n")
assert "\n" not in raw and "\r" not in raw and "\t" not in raw, "unescaped control char in output"
PY

# ---- null typing: peak/status/teardown_rc are null (not "") when not produced ----
line="$(run_ok "" fail "" systemd img id linux amd64 "" tag c r "" "" "" 0 "" "" "")"
python3 - "$line" <<'PY' && ok "not-produced numerics decode to null (never stringified empties)" || exit 1
import json,sys
d=json.loads(sys.argv[1])
assert d["memory_peak_bytes"] is None
assert d["workload_exit_status"] is None
assert d["teardown_rc"] is None
assert d["cleanup_ok"] is False
PY

# ---- exactly one JSON object per line across appends ----
: > "$WORK/multi.jsonl"
run_ok "$WORK/multi.jsonl" pass "" systemd i id linux amd64 "" tag c r cg 1 0 1 a 0 "" >/dev/null
run_ok "$WORK/multi.jsonl" pass "" systemd i id linux amd64 "" tag c r cg 2 0 1 a 0 "" >/dev/null
n="$(wc -l <"$WORK/multi.jsonl" | tr -d ' ')"
python3 - "$WORK/multi.jsonl" <<'PY' && [ "$n" = 2 ] && ok "exactly one complete JSON object per JSONL line" || fail "multi-line ($n)"
import json,sys
for ln in open(sys.argv[1]):
    ln=ln.rstrip("\n")
    if ln: json.loads(ln)  # each line is a complete object or it raises
PY

# ---- fail-closed: encoder failure -> nonzero exit AND no partial line written ----
EF="$WORK/failclosed.jsonl"; : > "$EF"
python3 "$EMIT" "$EF" too few args >/dev/null 2>&1; rc=$?
{ [ "$rc" -ne 0 ] && [ "$(wc -c <"$EF" | tr -d ' ')" = 0 ]; } && ok "fail-closed: nonzero exit + no partial line" || fail "fail-closed (rc=$rc, bytes=$(wc -c <"$EF"))"

echo
if [ "$fails" -eq 0 ]; then echo "cgroup evidence: ALL PASS"; exit 0
else echo "cgroup evidence: $fails FAILED"; exit 1; fi
