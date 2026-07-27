#!/usr/bin/env bash
# OCI index platform-binding tests (finding F5).
#
# PIN-PROPOSAL.md documented that each per-arch base digest must belong to the target
# platform, but nothing implemented it: `docker manifest inspect` resolves any digest
# regardless of platform, so the two per-arch digests could be SWAPPED and still pass.
# These tests exercise `verify_oci_index_platforms` against a committed SYNTHETIC index
# fixture. No network, no Docker, and — crucially — no image is ever executed, so the
# guarantee holds identically on a host with QEMU/binfmt registered.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS="$(cd "$HERE/.." && pwd)"
FIX="$HERE/fixtures/oci-index.sample.json"
# shellcheck source=../lib.sh
. "$SCRIPTS/lib.sh"
set +e

fails=0
ok()  { printf 'ok    %s\n' "$1"; }
bad() { printf 'FAIL  %s\n' "$1" >&2; fails=$((fails + 1)); }

command -v python3 >/dev/null 2>&1 || { echo "SKIP: python3 absent"; exit 0; }
[ -f "$FIX" ] || { echo "FAIL: fixture $FIX missing" >&2; exit 1; }

digest_for() { # <label> -> the fixture digest whose platform matches
  python3 - "$FIX" "$1" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1])); want = sys.argv[2]
sel = {"amd64": ("linux", "amd64"), "arm64": ("linux", "arm64"),
       "armv7": ("linux", "arm"), "winamd64": ("windows", "amd64")}[want]
for m in doc["manifests"]:
    p = m.get("platform") or {}
    if (p.get("os"), p.get("architecture")) == sel:
        print(m["digest"]); break
PY
}

AMD="$(digest_for amd64)"
ARM="$(digest_for arm64)"
ARMV7="$(digest_for armv7)"
WIN="$(digest_for winamd64)"
ABSENT="sha256:$(printf 'not-a-child-of-this-index' | sha256_hex_stdin)"

# 1. the correct pairing is accepted
if verify_oci_index_platforms "$FIX" "$AMD" "$ARM" >/dev/null 2>&1; then
  ok "correct pairing accepted (x86_64->linux/amd64, aarch64->linux/arm64)"
else
  bad "correct pairing should be accepted"
fi

# 2. THE regression this exists for: swapping the two digests must be rejected.
out="$(verify_oci_index_platforms "$FIX" "$ARM" "$AMD" 2>&1)"
if [ $? -ne 0 ] && printf '%s' "$out" | grep -q "swapped or wrong-arch digest"; then
  ok "SWAPPED per-arch digests rejected (no image executed)"
else
  bad "swapped digests must be rejected; got: $out"
fi

# 3. a digest that is not a child of the pinned index is rejected
out="$(verify_oci_index_platforms "$FIX" "$ABSENT" "$ARM" 2>&1)"
if [ $? -ne 0 ] && printf '%s' "$out" | grep -q "NOT a child of the pinned index"; then
  ok "digest outside the pinned index rejected"
else
  bad "non-child digest must be rejected; got: $out"
fi

# 4. a child of the index but the WRONG linux architecture (arm/v7) is rejected
out="$(verify_oci_index_platforms "$FIX" "$AMD" "$ARMV7" 2>&1)"
if [ $? -ne 0 ] && printf '%s' "$out" | grep -q "platform.architecture"; then
  ok "wrong-architecture child (linux/arm/v7 as aarch64) rejected"
else
  bad "wrong-arch child must be rejected; got: $out"
fi

# 5. right architecture, wrong OS (windows/amd64) is rejected
out="$(verify_oci_index_platforms "$FIX" "$WIN" "$ARM" 2>&1)"
if [ $? -ne 0 ] && printf '%s' "$out" | grep -q "expected 'linux'"; then
  ok "non-linux child (windows/amd64) rejected"
else
  bad "non-linux child must be rejected; got: $out"
fi

# 6. the same digest proposed for both arches is rejected
out="$(verify_oci_index_platforms "$FIX" "$AMD" "$AMD" 2>&1)"
if [ $? -ne 0 ]; then
  ok "identical digest for both architectures rejected"
else
  bad "identical per-arch digests must be rejected"
fi

# 7. a document with no manifests array is rejected (not silently passed)
tmp="${TMPDIR:-/tmp}/ociplat.$$.json"
printf '{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json"}\n' > "$tmp"
out="$(verify_oci_index_platforms "$tmp" "$AMD" "$ARM" 2>&1)"
if [ $? -ne 0 ] && printf '%s' "$out" | grep -q "no 'manifests' array"; then
  ok "single manifest (not an index) rejected"
else
  bad "a non-index document must be rejected; got: $out"
fi
rm -f "$tmp"

echo "----"
if [ "$fails" -eq 0 ]; then echo "oci_platform: ALL TESTS PASS"; exit 0
else echo "oci_platform: $fails FAILURE(S)" >&2; exit 1; fi
