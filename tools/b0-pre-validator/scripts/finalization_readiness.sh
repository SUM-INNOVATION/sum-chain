#!/usr/bin/env bash
# Finalization-readiness report for the normative protocol artifact.
#
# Reads the committed artifact (no network, read-only) and reports whether it is
# finalizable, which implementation-produced fields are still absent, and that
# the final b0_pre_spec_hash is therefore blocked. Exit 0 = state is internally
# consistent (finalizable iff no field is absent); non-zero = inconsistent, or a
# fabricated implementation-produced field leaked into a not_finalizable artifact.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
ART="$ROOT/docs/b0-pre/protocol/b0-pre-protocol-v1.json"

python3 - "$ART" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
state = d["finalization"]["state"]
blocked = d["finalization"]["blocked_on"]
present = list(d.get("pending_inputs", {}).keys())

print(f"artifact_id:      {d['artifact_id']}")
print(f"spec_version:     {d['spec_version']}")
print(f"finalization:     {state}")
print(f"blocked_on:       {', '.join(blocked) if blocked else '(none)'}")
print(f"pending present:  {', '.join(present) if present else '(none)'}")
print(f"protocol hash:    {'BLOCKED' if state != 'finalizable' else 'unblocked'}")

ok = True
# consistency: not_finalizable iff at least one field is absent
absent = len(blocked) > 0
if (state == "not_finalizable") != absent:
    print("FAIL: finalization.state inconsistent with blocked_on")
    ok = False
# no implementation-produced field may be present while not finalizable
if state != "finalizable" and present:
    print("FAIL: implementation-produced field present in a not_finalizable artifact")
    ok = False
print("READY to finalize" if state == "finalizable" and not present else
      "NOT READY: implementation-produced fields must exist first")
sys.exit(0 if ok else 1)
PY
