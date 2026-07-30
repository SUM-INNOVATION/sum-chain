#!/usr/bin/env bash
# Builder-image CAPABILITY preflight negatives (Item 6). Drives the SHARED production function
# lib.sh:preflight_builder_capability against real, minimal Docker images and asserts it FAILS
# CLOSED — validating versions + identities, not a bare `command -v` — on:
#   * cargo-audit absent;
#   * cargo-audit present but the WRONG version;
#   * an architecture that does not match the image;
#   * RT-2 login-PATH loss (tools on a login-only PATH, invisible to the production `bash -c`);
# and PASSES on a correctly-provisioned image (cargo + cargo-audit at the pinned version).
#
# The images bake tiny FAKE `cargo` / `cargo-audit` shims (no real toolchain), so the test is
# fast and hermetic. Opt-in (needs Docker); skips cleanly unless B0PRE_DOCKER_IT=1 (or CI's
# B0PRE_E2E_REQUIRED=1). Nothing authoritative runs; no evidence is produced.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCR="$(cd "$HERE/.." && pwd)"
REQUIRED="${B0PRE_E2E_REQUIRED:-0}"
BASE="${B0PRE_CAP_BASE_IMAGE:-debian:bookworm-slim}"

skip_or_fail() {
  if [ "$REQUIRED" = "1" ]; then printf 'FAIL (required mode): %s\n' "$1" >&2; exit 1; fi
  printf 'SKIP (docker): %s\n' "$1"
  printf '\nbuilder_capability: SKIPPED (opt-in; set B0PRE_DOCKER_IT=1 or B0PRE_E2E_REQUIRED=1)\n'
  exit 0
}
[ "${B0PRE_DOCKER_IT:-}" = "1" ] || [ "$REQUIRED" = "1" ] || skip_or_fail "opt-in flag not set"
command -v docker >/dev/null 2>&1 || skip_or_fail "docker not on PATH"
docker version >/dev/null 2>&1 || skip_or_fail "docker daemon not reachable"

# shellcheck source=../lib.sh
. "$SCR/lib.sh" >/dev/null 2>&1

T="$(mktemp -d "$HOME/.b0-cap-XXXXXX")"; trap 'rm -rf "$T"; docker rmi -f b0-cap-good b0-cap-noaudit b0-cap-badver b0-cap-loginpath >/dev/null 2>&1 || true' EXIT
F=0; ok(){ printf 'ok    %s\n' "$1"; }; bad(){ printf 'FAIL  %s\n' "$1" >&2; F=1; }

# preflight_builder_capability calls `die` (exit 2) on failure; run it in a SUBSHELL so a
# fail-closed image does not abort the test. expect_fail => PASS when the gate exits nonzero.
gate() { ( preflight_builder_capability "$@" ) >/dev/null 2>&1; }
expect_pass() { local label="$1"; shift; if gate "$@"; then ok "$label (gate PASSES)"; else bad "$label — gate should PASS but failed"; fi; }
expect_fail() { local label="$1"; shift; if gate "$@"; then bad "$label — gate should FAIL CLOSED but passed"; else ok "$label (gate fails closed)"; fi; }

# Native arch of this host's containers (colima is aarch64; CI amd64) — used to build a real
# arch-mismatch negative by declaring the OTHER arch.
NARCH="$(docker run --rm --pull never "$BASE" uname -m 2>/dev/null || docker run --rm "$BASE" uname -m 2>/dev/null)"
case "$NARCH" in
  x86_64)  OTHER_ARCH=aarch64 ;;
  aarch64) OTHER_ARCH=x86_64 ;;
  *) skip_or_fail "unexpected container arch '$NARCH'" ;;
esac

# ---- image builders (tiny fake shims; no real toolchain) ---------------------------------
# good: cargo + cargo-audit@0.22.2 on the base ENV PATH.
build_img() { # <tag> <extra Dockerfile lines file>
  docker build -q -t "$1" -f "$2" "$T" >/dev/null 2>"$T/build.err" || { bad "image build $1"; cat "$T/build.err" >&2; return 1; }
}
# Fake shims: cargo dispatches `audit` to cargo-audit; cargo-audit prints a version line.
cat > "$T/cargo" <<'SH'
#!/bin/sh
if [ "$1" = audit ]; then shift; exec cargo-audit "$@"; fi
echo "cargo 1.88.0 (fake shim)"
SH

mk_audit() { printf '#!/bin/sh\necho "cargo-audit-audit %s"\n' "$1" > "$T/cargo-audit"; }

# good image
mk_audit "0.22.2"
cat > "$T/Dockerfile.good" <<EOF
FROM $BASE
COPY cargo /usr/local/bin/cargo
COPY cargo-audit /usr/local/bin/cargo-audit
RUN chmod +x /usr/local/bin/cargo /usr/local/bin/cargo-audit
EOF
build_img b0-cap-good "$T/Dockerfile.good"

# no-cargo-audit image (cargo present, cargo-audit absent)
cat > "$T/Dockerfile.noaudit" <<EOF
FROM $BASE
COPY cargo /usr/local/bin/cargo
RUN chmod +x /usr/local/bin/cargo
EOF
build_img b0-cap-noaudit "$T/Dockerfile.noaudit"

# wrong-version image (cargo-audit@0.21.0)
mk_audit "0.21.0"
cat > "$T/Dockerfile.badver" <<EOF
FROM $BASE
COPY cargo /usr/local/bin/cargo
COPY cargo-audit /usr/local/bin/cargo-audit
RUN chmod +x /usr/local/bin/cargo /usr/local/bin/cargo-audit
EOF
build_img b0-cap-badver "$T/Dockerfile.badver"

# RT-2 login-only PATH: tools live in /opt/tools, exported ONLY via /etc/profile.d (login),
# so a NON-login `bash -c` cannot see them.
mk_audit "0.22.2"
cat > "$T/Dockerfile.loginpath" <<EOF
FROM $BASE
COPY cargo /opt/tools/cargo
COPY cargo-audit /opt/tools/cargo-audit
RUN chmod +x /opt/tools/cargo /opt/tools/cargo-audit \
 && printf 'export PATH=/opt/tools:\$PATH\n' > /etc/profile.d/b0tools.sh
EOF
build_img b0-cap-loginpath "$T/Dockerfile.loginpath"

# ---- assertions --------------------------------------------------------------------------
# positive: correctly provisioned image passes (with the pinned version asserted).
expect_pass "good image (cargo + cargo-audit@0.22.2 on ENV PATH)" b0-cap-good "$NARCH" "0.22.2"
# and passes when no version pin is supplied (still requires cargo-audit present).
expect_pass "good image, no version pin (cargo-audit still required present)" b0-cap-good "$NARCH"
# negative: cargo-audit absent.
expect_fail "cargo-audit absent" b0-cap-noaudit "$NARCH" "0.22.2"
# negative: wrong cargo-audit version.
expect_fail "cargo-audit wrong version (0.21.0 != pinned 0.22.2)" b0-cap-badver "$NARCH" "0.22.2"
# negative: architecture mismatch (declare the OTHER arch than the image really is).
expect_fail "architecture mismatch ($OTHER_ARCH declared, image is $NARCH)" b0-cap-good "$OTHER_ARCH" "0.22.2"
# negative: RT-2 login-PATH loss (tools invisible to the production non-login bash -c).
expect_fail "RT-2 login-only PATH (cargo not on the non-login PATH)" b0-cap-loginpath "$NARCH" "0.22.2"
# control: the RT-2 image DOES resolve the tools under a LOGIN shell (proving the negative is
# specifically the non-login/login distinction, not a broken image).
if docker run --rm --pull never b0-cap-loginpath bash -lc 'command -v cargo cargo-audit >/dev/null' 2>/dev/null; then
  ok "RT-2 control: the same image resolves cargo+cargo-audit under a LOGIN shell (bash -lc)"
else
  bad "RT-2 control: login shell should have resolved the tools"
fi

echo "----"
if [ "$F" = 0 ]; then
  # Terminal marker: required CI greps for this to prove the test EXECUTED (a SKIP prints its
  # own line and never this marker), so a skipped/absent run fails the required check.
  echo "BUILDER_CAPABILITY_PASS"
  echo "builder_capability: ALL TESTS PASS"; exit 0
else echo "builder_capability: FAILURE(S)" >&2; exit 1; fi
