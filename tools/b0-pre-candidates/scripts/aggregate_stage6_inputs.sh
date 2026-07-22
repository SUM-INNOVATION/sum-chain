#!/usr/bin/env bash
# Aggregate the per-(candidate, arch) producer outputs from Stages 1-5 into the
# EXACT aggregate files the Stage-6 assembler consumes:
#
#   *.container.json (2-entry OciBuild arrays) -> digests.json          {"builds":[...]}
#   *.native.json    (1-entry NativeBuild arrays) -> native-provenance.json {"native_builds":[...]}
#   *.tool.json      (per-candidate ToolIdentityInput) -> tool-identities.json {"tool_identities":[...]}
#
# This aggregation logic runs OFF-VENUE (no Docker/toolchains needed), so it is the
# real code the producer→consumer compatibility test exercises. It performs no
# reshaping beyond concatenation: each source object is emitted verbatim into the
# aggregate the assembler decodes.
#
# Usage: aggregate_stage6_inputs.sh <work_dir>
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib.sh
. "$HERE/lib.sh"
require_cmd python3

work="${1:-}"
[ -n "$work" ] || die "work directory argument required"
[ -d "$work" ] || die "work directory $work does not exist"

python3 - "$work" <<'PY'
import glob, json, os, sys
work = sys.argv[1]

def load_all(pattern):
    out = []
    for path in sorted(glob.glob(os.path.join(work, pattern))):
        with open(path) as f:
            data = json.load(f)
        # each producer file is a JSON array of entries; concatenate verbatim.
        if not isinstance(data, list):
            raise SystemExit(f"REFUSED: {path} is not a JSON array of entries")
        out.extend(data)
    return out

builds = load_all("*.container.json")
if not builds:
    raise SystemExit("REFUSED: no *.container.json producer outputs to aggregate")
native = load_all("*.native.json")
if not native:
    raise SystemExit("REFUSED: no *.native.json producer outputs to aggregate")

tools = []
for path in sorted(glob.glob(os.path.join(work, "*.tool.json"))):
    with open(path) as f:
        tools.append(json.load(f))   # per-candidate object, verbatim
if not tools:
    raise SystemExit("REFUSED: no *.tool.json producer outputs to aggregate")

def write(name, obj):
    with open(os.path.join(work, name), "w") as f:
        json.dump(obj, f, indent=2); f.write("\n")

write("digests.json", {"builds": builds})
write("native-provenance.json", {"native_builds": native})
write("tool-identities.json", {"tool_identities": tools})
print(f"aggregated {len(builds)} container builds, {len(native)} native builds, "
      f"{len(tools)} tool-identity entries")
PY
note "wrote $work/{digests,native-provenance,tool-identities}.json"
