#!/usr/bin/env python3
"""Robust JSONL evidence emitter for the B0-FINAL cgroup validation.

`json.dumps` performs ALL escaping (quotes, backslashes, \\n / \\r / \\t, and other control
characters as \\uXXXX) and preserves JSON types (strings stay strings, numbers stay numbers, booleans
stay booleans). The complete line is built BEFORE any write, so a partial evidence line is never
emitted: on ANY encoder error the process exits non-zero and writes nothing.

Types: memory_peak_bytes / workload_exit_status / teardown_rc are JSON numbers when present, and JSON
null ONLY where the field was legitimately not produced (no peak captured / teardown not attempted) —
never a stringified empty value. cleanup_ok is a JSON boolean. Every string field is a JSON string,
including "" (empty strings decode to "", never to a missing field or null).

Usage: emit_cgroup_evidence.py <evidence_path|""> <result> <detail> <driver> <image_ref> <image_id>
       <image_os> <image_arch> <image_repo_digests> <image_immutability> <container_cmd> <run_cmd>
       <resolved_cgroup> <memory_peak_bytes> <workload_exit_status> <cleanup_ok(1|0)>
       <teardown_argv> <teardown_rc> <teardown_stderr>
Writes the line to <evidence_path> (when non-empty) and to stdout. Exit 0 on success.
"""
import json
import sys


def _num_or_null(s):
    if s == "":
        return None
    try:
        return int(s)
    except ValueError:
        return None


def main():
    a = sys.argv[1:]
    if len(a) != 19:
        sys.stderr.write("emit_cgroup_evidence: expected 19 args, got %d\n" % len(a))
        return 2
    evidence_path = a[0]
    rec = {
        "kind": "b0pre-cgroup-validation/v4",
        "result": a[1],
        "detail": a[2],
        "driver": a[3],
        "image_ref": a[4],
        "image_id": a[5],
        "platform": a[6] + "/" + a[7],
        "image_repo_digests": a[8],
        "image_immutability": a[9],
        "pull": "never",
        "container_cmd": a[10],
        "run_cmd": a[11],
        "resolved_cgroup": a[12],
        "memory_peak_bytes": _num_or_null(a[13]),
        "workload_exit_status": _num_or_null(a[14]),
        "cleanup_ok": (a[15] == "1"),
        "teardown_argv": a[16],
        "teardown_rc": _num_or_null(a[17]),
        "teardown_stderr": a[18],
    }
    # Build the ENTIRE line first (this is where any encoding error surfaces) — only then write, so a
    # partial/invalid line can never reach the evidence file.
    line = json.dumps(rec, ensure_ascii=True, sort_keys=True)
    if evidence_path:
        with open(evidence_path, "a", encoding="ascii") as f:
            f.write(line + "\n")
    sys.stdout.write(line + "\n")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # fail closed: no partial line, non-zero exit
        sys.stderr.write("emit_cgroup_evidence: encoder failed: %s\n" % exc)
        sys.exit(3)
