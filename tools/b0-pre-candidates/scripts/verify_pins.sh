#!/usr/bin/env bash
# Automated verification of a PROPOSED immutable venue-input pin set against its PRIMARY
# sources (see docs/b0-pre/venue/PIN-PROPOSAL.md). Reads a proposed-pins JSON, re-derives
# each pin from its primary source, and FAILS CLOSED on any mismatch or non-primary source.
#
# It contains NO pin values, edits NO repo file, and never ratifies: a clean run is only a
# PRECONDITION for owner ratification, never ratification itself.
#
# Contract v2 (resolves the native-x86 pin-audit findings F1, F2, F5, F6, F7, F8):
#   * rustup-init is pinned by an EXACT IMMUTABLE archive URL per architecture; the
#     unversioned `rustup/dist/` path is refused outright (F1).
#   * the APT pin is four exact fields — two snapshot base URLs and the two expected
#     InRelease sha256 values — instead of a bare timestamp, so the verifier and both
#     Dockerfiles consume the SAME fields (F2) and a timestamp that merely redirects to a
#     preceding snapshot is caught by the content hash (F8).
#   * the base image's immutable OCI INDEX is resolved and its child manifests are
#     enumerated, binding each per-arch digest to its declared platform, so a swapped pair
#     fails without executing either image (F5).
#   * download hosts are matched EXACTLY, over https, on both the initial and the
#     effective (post-redirect) URL (F6, F7).
#
# Usage: verify_pins.sh <proposed-pins.json>
# Requires: python3, curl, a sha256 tool (sha256sum/shasum), docker (base index resolution).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib.sh
. "$HERE/lib.sh"

PINS="${1:-}"
[ -n "$PINS" ] && [ -f "$PINS" ] || die "usage: verify_pins.sh <proposed-pins.json>"
require_cmd python3
require_cmd curl

# The logical installer version the repository requires for Rust 1.88.0.
REQUIRED_RUSTUP_VERSION="1.29.0"
# The suites both Dockerfiles enable from the two pinned snapshot sources.
APT_DEBIAN_SUITE="bookworm"
APT_SECURITY_SUITE="bookworm-security"

fail=0
pass() { printf 'PASS  %s\n' "$*"; }
bad()  { printf 'FAIL  %s\n' "$*" >&2; fail=1; }

# Read a dotted path (supporting name[idx]) out of the proposed-pins JSON; empty if absent.
pget() {
  python3 - "$PINS" "$1" <<'PY' 2>/dev/null || true
import json, sys
d = json.load(open(sys.argv[1]))
cur = d
for k in sys.argv[2].split("."):
    if k.endswith("]"):
        name, idx = k[:-1].split("[")
        cur = cur[name][int(idx)] if name else cur[int(idx)]
    else:
        cur = cur[k]
print(cur if cur is not None else "")
PY
}

# sha256 of a URL's content (streamed, never written to disk). Fails (non-zero) when the
# fetch fails, so an unreachable URL can never be mistaken for "hashed successfully".
sha256_of_url() {
  local body
  body="$(curl -fsSL --max-redirs 5 "$1" | sha256_hex_stdin)" || return 1
  [ -n "$body" ] || return 1
  printf '%s' "$body"
}

is_full_sha256_digest() { printf '%s' "${1#sha256:}" | grep -Eq '^[0-9a-f]{64}$' && [ "${1#sha256:}" != "$1" ]; }
is_bare_sha256()        { printf '%s' "${1:-}" | grep -Eq '^[0-9a-f]{64}$'; }

# ---- (1) base image: immutable index + per-arch child platform binding -------
base_image="$(pget base_image)"
index_digest="$(pget base_index_digest)"
d_x86="$(pget base_digest.x86_64)"
d_arm="$(pget base_digest.aarch64)"

[ -n "$base_image" ] || bad "base_image is missing"
if [ -z "$index_digest" ]; then
  bad "base_index_digest is missing (the immutable OCI index the per-arch digests must belong to)"
elif ! is_full_sha256_digest "$index_digest"; then
  bad "base_index_digest is not a full sha256:<64hex> digest: $index_digest"
fi
for pair in "x86_64:$d_x86" "aarch64:$d_arm"; do
  a="${pair%%:*}"; v="${pair#*:}"
  [ -n "$v" ] || { bad "base_digest.$a is missing"; continue; }
  is_full_sha256_digest "$v" || bad "base_digest.$a is not a full sha256:<64hex> digest: $v"
done

if [ -n "$base_image" ] && [ -n "$index_digest" ] && [ -n "$d_x86" ] && [ -n "$d_arm" ] \
   && is_full_sha256_digest "$index_digest" && is_full_sha256_digest "$d_x86" && is_full_sha256_digest "$d_arm"; then
  if ! command -v docker >/dev/null 2>&1; then
    bad "docker is required to resolve the base OCI index and validate child platforms; it is absent"
  else
    idx_json="$(mktemp)"
    if ! docker manifest inspect "$base_image@$index_digest" > "$idx_json" 2>/dev/null; then
      bad "base_index_digest does NOT resolve by pull-by-digest: $base_image@$index_digest"
    else
      pass "base index resolves by digest ($base_image@$index_digest)"
      # Enumerate the index's children and bind each proposed digest to its PLATFORM.
      # Metadata only: no image is pulled or executed, so a host with QEMU/binfmt
      # registered cannot mask a swapped pair.
      if plat_err="$(verify_oci_index_platforms "$idx_json" "$d_x86" "$d_arm" 2>&1)"; then
        pass "base_digest.x86_64 -> linux/amd64 and base_digest.aarch64 -> linux/arm64, both children of the pinned index"
      else
        bad "base image platform validation failed: $plat_err"
      fi
    fi
    rm -f "$idx_json"
  fi
fi

# ---- (2) APT: two pinned snapshot URLs + two expected InRelease sha256 -------
# The bare-timestamp contract could not be verified: snapshot.debian.org resolves ANY
# timestamp to the nearest PRECEDING snapshot, so "reachable + immutable" passed even for
# a nonexistent date. The InRelease content hash is the real identity, and it is what both
# Dockerfiles re-check before apt installs anything.
apt_check() {
  local label="$1" url="$2" want="$3" suite="$4" got
  if [ -z "$url" ] || [ -z "$want" ]; then
    bad "apt.${label}_url / apt.${label}_inrelease_sha256 missing"; return
  fi
  require_apt_pin_url "apt.${label}_url" "$url" || { fail=1; return; }
  is_bare_sha256 "$want" || { bad "apt.${label}_inrelease_sha256 is not a bare 64-hex sha256: $want"; return; }
  local inrel="${url}dists/${suite}/InRelease"
  # The snapshot service answers with a redirect to a content-addressed path on the SAME
  # host. Refuse a redirect off that host, and refuse an https->http downgrade.
  if ! require_apt_redirect_chain "apt.${label}_url" "$inrel" >/dev/null; then fail=1; return; fi
  if ! got="$(sha256_of_url "$inrel")"; then
    bad "apt.${label}: InRelease not reachable at $inrel"; return
  fi
  if [ "$got" = "$want" ]; then
    pass "apt.${label} InRelease sha256 matches the pinned value (${suite})"
  else
    bad "apt.${label} InRelease sha256 MISMATCH (served=$got pinned=$want) — the URL served a DIFFERENT snapshot than pinned"
  fi
}
apt_check "debian"          "$(pget apt.debian_url)"          "$(pget apt.debian_inrelease_sha256)"          "$APT_DEBIAN_SUITE"
apt_check "debian_security" "$(pget apt.debian_security_url)" "$(pget apt.debian_security_inrelease_sha256)" "$APT_SECURITY_SUITE"

# ---- (3) per-arch rustup-init: EXACT immutable archive URL + checksum --------
rustup_version="$(pget rustup_init.version)"
if [ -z "$rustup_version" ]; then
  bad "rustup_init.version is missing (must be $REQUIRED_RUSTUP_VERSION)"
elif [ "$rustup_version" != "$REQUIRED_RUSTUP_VERSION" ]; then
  bad "rustup_init.version is '$rustup_version'; the repository requires rustup $REQUIRED_RUSTUP_VERSION for Rust 1.88.0"
fi

for arch in x86_64 aarch64; do
  url="$(pget "rustup_init.$arch.url")"
  want="$(pget "rustup_init.$arch.sha256")"
  [ -n "$url" ] && [ -n "$want" ] || { bad "rustup_init.$arch url/sha256 missing"; continue; }
  is_bare_sha256 "$want" || { bad "rustup_init.$arch sha256 is not a bare 64-hex value: $want"; continue; }
  require_https_primary_url "rustup_init.$arch.url" "$url" || { fail=1; continue; }

  # Refuse the UNVERSIONED, MUTABLE distribution path outright: it always serves the
  # newest rustup, so it cannot preregister bytes (finding F1).
  case "$url" in
    */rustup/dist/*) bad "rustup_init.$arch.url uses the MUTABLE unversioned rustup/dist/ path; pin rustup/archive/$REQUIRED_RUSTUP_VERSION/ instead: $url"; continue ;;
  esac
  # Require the EXACT immutable archive locator for the required version and this arch.
  case "$url" in
    *"/rustup/archive/$REQUIRED_RUSTUP_VERSION/$arch-unknown-linux-gnu/rustup-init") ;;
    *) bad "rustup_init.$arch.url is not the exact immutable archive locator .../rustup/archive/$REQUIRED_RUSTUP_VERSION/$arch-unknown-linux-gnu/rustup-init: $url"; continue ;;
  esac

  if ! got="$(sha256_of_url "$url")"; then
    bad "rustup_init.$arch artifact not reachable: $url"; continue
  fi
  if [ "$got" = "$want" ]; then
    pass "rustup_init.$arch ($REQUIRED_RUSTUP_VERSION) sha256 matches primary source"
  else
    bad "rustup_init.$arch sha256 MISMATCH (source=$got proposed=$want)"
  fi
done

# ---- (4/5) tool identities: per-arch, redirect-validated, checksum-bound -----
count="$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1])).get("tool_identities",[])))' "$PINS" 2>/dev/null || echo 0)"
seen_sp1_x86=0; seen_sp1_arm=0; seen_r0_zkvm=0; seen_r0_g16=0
i=0
while [ "$i" -lt "$count" ]; do
  name="$(pget "tool_identities[$i].name")"
  ver="$(pget "tool_identities[$i].version")"
  tarch="$(pget "tool_identities[$i].arch")"
  url="$(pget "tool_identities[$i].artifact_identity")"
  algo="$(pget "tool_identities[$i].checksum_algorithm")"
  want="$(pget "tool_identities[$i].checksum_hex")"
  entry="$(pget "tool_identities[$i].install_entrypoint")"

  if [ -z "$name" ] || [ -z "$url" ] || [ -z "$want" ] || [ -z "$entry" ] || [ -z "$tarch" ]; then
    bad "tool_identities[$i] ($name) has an absent field (name/arch/artifact_identity/checksum_hex/install_entrypoint)"
    i=$((i + 1)); continue
  fi
  case "$tarch" in x86_64|aarch64) ;; *) bad "tool_identities[$i] ($name) arch must be x86_64|aarch64 (got '$tarch')"; i=$((i + 1)); continue ;; esac
  [ "$algo" = "sha256" ] || { bad "tool_identities[$i] ($name) checksum_algorithm must be sha256 (got '$algo')"; i=$((i + 1)); continue; }
  is_bare_sha256 "$want" || { bad "tool_identities[$i] ($name) checksum_hex is not a bare 64-hex value"; i=$((i + 1)); continue; }

  # RISC Zero is native-x86_64-only under VENUE.md §2 and upstream publishes no
  # aarch64-linux artifact; an aarch64 RISC Zero identity is refused, not downgraded.
  case "$name/$tarch" in
    risc0-*/aarch64) bad "tool_identities[$i] ($name) declares arch=aarch64; RISC Zero is native-x86_64-only (VENUE.md §2)"; i=$((i + 1)); continue ;;
  esac

  if ! eff_host="$(require_allowed_redirect_chain "tool_identities[$i].artifact_identity" "$url")"; then
    fail=1; i=$((i + 1)); continue
  fi
  if ! got="$(sha256_of_url "$url")"; then
    bad "tool_identity $name@$ver ($tarch) artifact not reachable: $url"; i=$((i + 1)); continue
  fi
  if [ "$got" = "$want" ]; then
    pass "tool_identity $name@$ver ($tarch) checksum matches primary source (delivered by $eff_host)"
    case "$name/$tarch" in
      sp1-verifier/x86_64)  seen_sp1_x86=1 ;;
      sp1-verifier/aarch64) seen_sp1_arm=1 ;;
      risc0-zkvm/x86_64)    seen_r0_zkvm=1 ;;
      risc0-groth16/x86_64) seen_r0_g16=1 ;;
    esac
  else
    bad "tool_identity $name@$ver ($tarch) checksum MISMATCH (source=$got proposed=$want)"
  fi
  i=$((i + 1))
done

# Required coverage: SP1 on BOTH native architectures, RISC Zero on x86_64 only.
[ "$seen_sp1_x86" = 1 ] || bad "no verified sp1-verifier tool identity for x86_64"
[ "$seen_sp1_arm" = 1 ] || bad "no verified sp1-verifier tool identity for aarch64"
[ "$seen_r0_zkvm" = 1 ] || bad "no verified risc0-zkvm tool identity for x86_64"
[ "$seen_r0_g16"  = 1 ] || bad "no verified risc0-groth16 tool identity for x86_64"

echo "----"
if [ "$fail" -eq 0 ]; then
  note "all proposed pins verified against their primary sources (this is a PRECONDITION for ratification, not ratification)"
else
  die "one or more proposed pins failed primary-source verification; NOT eligible for ratification"
fi
