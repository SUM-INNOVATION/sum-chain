#!/usr/bin/env bash
# Pin-schema reconciliation tests (Blocker 1a).
#
# Proves the documented proposed-pins shape (docs/b0-pre/venue/PIN-PROPOSAL.md and its
# committed fixture) is EXACTLY the shape verify_pins.sh reads, that the previous wrong
# shape is discriminated, that verify_pins actually resolves the corrected
# rustup_init.<arch>.url path, and that empty/UNRATIFIED values still fail closed.
# No network is performed: every verify_pins run here refuses before any fetch.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS="$(cd "$HERE/.." && pwd)"
FIXTURE="$HERE/fixtures/proposed-pins.documented-shape.json"
VERIFY="$SCRIPTS/verify_pins.sh"
TMPD="${TMPDIR:-/tmp}"
set +e
fails=0
ok()  { printf 'ok    %s\n' "$1"; }
bad() { printf 'FAIL  %s\n' "$1" >&2; fails=$((fails + 1)); }

command -v python3 >/dev/null 2>&1 || { echo "SKIP: python3 absent (verify_pins requires it)"; exit 0; }

# The exact dotted paths verify_pins.sh reads via pget (kept in lockstep with the
# script; a schema change in one must change the other).
read_paths='base_image
base_digest.x86_64
base_digest.aarch64
apt_snapshot
rustup_init.x86_64.url
rustup_init.x86_64.sha256
rustup_init.aarch64.url
rustup_init.aarch64.sha256
tool_identities[0].name
tool_identities[0].version
tool_identities[0].artifact_identity
tool_identities[0].checksum_algorithm
tool_identities[0].checksum_hex
tool_identities[0].install_entrypoint'

# Exit 0 iff the pget-style dotted path resolves in the JSON file (value may be empty).
path_present() { # <json> <dotted.path>
  python3 - "$1" "$2" <<'PY'
import json, sys
cur = json.load(open(sys.argv[1]))
for k in sys.argv[2].split("."):
    if k.endswith("]"):
        name, idx = k[:-1].split("[")
        cur = (cur[name] if name else cur)[int(idx)]
    else:
        cur = cur[k]
PY
}

# 1. JSON-shape match ONLY: every verify_pins read-path is present in the fixture. This
#    proves the documented shape parses at the right keys — it does NOT mean the pins are
#    valid or ratified (the empty values are rejected by verification, test 4).
miss=0
while IFS= read -r p; do
  [ -n "$p" ] || continue
  if ! path_present "$FIXTURE" "$p" 2>/dev/null; then bad "fixture missing documented path: $p"; miss=1; fi
done <<EOF
$read_paths
EOF
[ "$miss" = 0 ] && ok "documented fixture resolves every verify_pins.sh read-path (JSON shape only; NOT a valid/ratified pin set)"

# 2. Discrimination: the OLD wrong shape must FAIL the read-path check (proves the test
#    catches drift; rustup_init_sha256 has no per-arch .url).
wrong="$TMPD/pinschema.wrong.$$.json"
cat > "$wrong" <<'JSON'
{ "base_image":"", "base_digest":{"x86_64":"","aarch64":""}, "apt_snapshot":"",
  "rustup_init_sha256":{"x86_64":"","aarch64":""},
  "tool_identities":[{"name":"sp1-verifier","version":"6.3.1","artifact_identity":"","checksum_algorithm":"sha256","checksum_hex":"","install_entrypoint":""}] }
JSON
if path_present "$wrong" "rustup_init.x86_64.url" 2>/dev/null; then
  bad "control: old shape unexpectedly satisfied rustup_init.x86_64.url"
else
  ok "control: old rustup_init_sha256 shape correctly FAILS the read-path check"
fi
rm -f "$wrong"

if ! command -v curl >/dev/null 2>&1; then
  echo "SKIP tests 3-4: curl absent (verify_pins requires it); structural checks above stand"
else
  # 3. verify_pins RESOLVES the corrected path: a documented-shape fixture whose
  #    rustup_init.x86_64.url is a non-primary host is rejected FOR THE HOST (path was
  #    read) rather than reported missing. example.invalid (RFC 2606) is never fetched.
  probe="$TMPD/pinschema.probe.$$.json"
  python3 - "$FIXTURE" "$probe" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
d["rustup_init"]["x86_64"]["url"] = "https://example.invalid/rustup-init"
d["rustup_init"]["x86_64"]["sha256"] = "0" * 64
json.dump(d, open(sys.argv[2], "w"))
PY
  probe_out="$(bash "$VERIFY" "$probe" 2>&1)"; probe_rc=$?
  if printf '%s' "$probe_out" | grep -q "example.invalid" \
     && printf '%s' "$probe_out" | grep -qi "not an allow-listed primary source"; then
    ok "verify_pins resolves rustup_init.x86_64.url (non-primary host rejected)"
  else
    bad "verify_pins did not resolve rustup_init.x86_64.url; output: $probe_out"
  fi
  [ "$probe_rc" -ne 0 ] && ok "probe run is fail-closed (rc=$probe_rc)" || bad "probe run should be non-zero"
  rm -f "$probe"

  # 4. The committed empty/UNRATIFIED fixture: JSON parses, but pin VERIFICATION fails
  #    closed. A shape-valid empty proposal is NOT an acceptable ratified pin set.
  empty_out="$(bash "$VERIFY" "$FIXTURE" 2>&1)"; empty_rc=$?
  if [ "$empty_rc" -ne 0 ] && printf '%s' "$empty_out" | grep -qi "NOT eligible for ratification"; then
    ok "empty/UNRATIFIED fixture FAILS pin verification (fail-closed rc=$empty_rc; not eligible for ratification)"
  else
    bad "empty fixture must FAIL verification with 'NOT eligible'; rc=$empty_rc out: $empty_out"
  fi
  if printf '%s' "$empty_out" | grep -qi "Traceback"; then
    bad "verify_pins emitted a python traceback (structure did not parse)"
  else
    ok "fixture parses as JSON but verification rejects the empty pins (shape-valid != ratified)"
  fi
fi

echo "----"
if [ "$fails" -eq 0 ]; then echo "pin_schema: ALL TESTS PASS"; exit 0
else echo "pin_schema: $fails FAILURE(S)" >&2; exit 1; fi
