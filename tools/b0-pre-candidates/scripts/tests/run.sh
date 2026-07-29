#!/usr/bin/env bash
# B0-PRE venue-script test runner (Blocker 4 / Blocker 1a regression guards).
#
# Runs `bash -n` + (if present) `shellcheck -S error` over the affected scripts, then the
# deterministic unit tests. Runnable locally and wired into .github/workflows/b0-pre.yml
# so the disk-portability fix and the pin-schema reconciliation stay enforced. Needs no
# network, toolchain, GPU, or venue.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS="$(cd "$HERE/.." && pwd)"
rc=0

echo "== bash -n (syntax) =="
for s in lib.sh verify_pins.sh run_authoritative.sh build_container.sh preflight_venue.sh \
         tool_identities.sh resolve_lock.sh \
         tests/disk_free_gib.test.sh tests/pin_schema.test.sh tests/source_authority.test.sh \
         tests/pin_url_policy.test.sh tests/oci_platform.test.sh tests/tool_identity_arch.test.sh \
         tests/apt_pins.test.sh tests/tool_identity_threading.test.sh tests/oci_daemon_bridge.test.sh \
         tests/build_reproducibility.test.sh tests/runnable_ref_sidecar.test.sh tests/rustup_components.test.sh tests/run.sh; do
  f="$SCRIPTS/$s"
  [ -f "$f" ] || continue
  if bash -n "$f"; then echo "  ok  $s"; else echo "  FAIL $s"; rc=1; fi
done

if command -v shellcheck >/dev/null 2>&1; then
  echo "== shellcheck -x -S error (source-follow SC1091 is info-level, not gated) =="
  if shellcheck -x -S error \
      "$SCRIPTS/lib.sh" "$SCRIPTS/verify_pins.sh" "$SCRIPTS/preflight_venue.sh" "$SCRIPTS/run_authoritative.sh" \
      "$SCRIPTS/build_container.sh" "$SCRIPTS/tool_identities.sh" "$SCRIPTS/resolve_lock.sh" \
      "$SCRIPTS/tests/disk_free_gib.test.sh" "$SCRIPTS/tests/pin_schema.test.sh" \
      "$SCRIPTS/tests/source_authority.test.sh" "$SCRIPTS/tests/pin_url_policy.test.sh" \
      "$SCRIPTS/tests/oci_platform.test.sh" "$SCRIPTS/tests/tool_identity_arch.test.sh" \
      "$SCRIPTS/tests/apt_pins.test.sh" "$SCRIPTS/tests/tool_identity_threading.test.sh" \
      "$SCRIPTS/tests/oci_daemon_bridge.test.sh" "$SCRIPTS/tests/build_reproducibility.test.sh" \
      "$SCRIPTS/tests/runnable_ref_sidecar.test.sh" "$SCRIPTS/tests/rustup_components.test.sh" "$SCRIPTS/tests/run.sh"; then
    echo "  ok  no error-level findings"
  else
    echo "  FAIL shellcheck error-level findings"; rc=1
  fi
else
  echo "== shellcheck absent — skipped =="
fi

echo "== unit tests =="
bash "$HERE/disk_free_gib.test.sh"     || rc=1
bash "$HERE/pin_schema.test.sh"        || rc=1
bash "$HERE/source_authority.test.sh"  || rc=1
bash "$HERE/pin_url_policy.test.sh"    || rc=1
bash "$HERE/oci_platform.test.sh"      || rc=1
bash "$HERE/tool_identity_arch.test.sh" || rc=1
bash "$HERE/apt_pins.test.sh"          || rc=1
bash "$HERE/tool_identity_threading.test.sh" || rc=1
bash "$HERE/oci_daemon_bridge.test.sh" || rc=1
bash "$HERE/build_reproducibility.test.sh"   || rc=1
bash "$HERE/runnable_ref_sidecar.test.sh"    || rc=1
bash "$HERE/rustup_components.test.sh"       || rc=1

echo "----"
if [ "$rc" = 0 ]; then echo "B0-PRE script tests: ALL PASS"; else echo "B0-PRE script tests: FAILURES" >&2; fi
exit "$rc"
