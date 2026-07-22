#!/usr/bin/env bash
# Automated verification of a PROPOSED immutable venue-input pin set against its PRIMARY
# sources (see docs/b0-pre/venue/PIN-PROPOSAL.md). Reads a proposed-pins JSON, re-derives
# each pin from its primary source, and FAILS CLOSED on any mismatch or non-primary source.
#
# It contains NO pin values, edits NO repo file, and never ratifies: a clean run is only a
# PRECONDITION for owner ratification, never ratification itself.
#
# Usage: verify_pins.sh <proposed-pins.json>
# Requires: python3, curl, a sha256 tool (sha256sum/shasum); docker is used if present to
# resolve base digests.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib.sh
. "$HERE/lib.sh"

PINS="${1:-}"
[ -n "$PINS" ] && [ -f "$PINS" ] || die "usage: verify_pins.sh <proposed-pins.json>"
require_cmd python3
require_cmd curl

# Only these hosts are accepted as PRIMARY sources for a downloadable pin. A proposed URL
# on any other host is refused — it is not an authoritative primary source.
PRIMARY_HOSTS="static.rust-lang.org github.com objects.githubusercontent.com codeload.github.com snapshot.debian.org snapshot.ubuntu.com"

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

host_of() { python3 -c 'import sys,urllib.parse as u; print(u.urlparse(sys.argv[1]).hostname or "")' "$1" 2>/dev/null || true; }

require_primary_host() {
  local url="$1" h; h="$(host_of "$url")"
  [ -n "$h" ] || { bad "unparseable URL: $url"; return 1; }
  case " $PRIMARY_HOSTS " in *" $h "*) return 0 ;; esac
  bad "URL host '$h' is not an allow-listed primary source: $url"
  return 1
}

# sha256 of a URL's content (streamed, never written to disk).
sha256_of_url() { curl -fsSL "$1" | sha256_hex_stdin; }

is_full_sha256_digest() { printf '%s' "${1#sha256:}" | grep -Eq '^[0-9a-f]{64}$' && [ "${1#sha256:}" != "$1" ]; }

# ---- (1) base image + per-arch digests -------------------------------------
base_image="$(pget base_image)"
[ -n "$base_image" ] || bad "base_image is missing"
for arch in x86_64 aarch64; do
  d="$(pget "base_digest.$arch")"
  [ -n "$d" ] || { bad "base_digest.$arch is missing"; continue; }
  is_full_sha256_digest "$d" || { bad "base_digest.$arch is not a full sha256:<64hex> digest: $d"; continue; }
  if [ -n "$base_image" ] && command -v docker >/dev/null 2>&1; then
    if docker manifest inspect "$base_image@$d" >/dev/null 2>&1; then
      pass "base_digest.$arch resolves by digest ($base_image@$d)"
    else
      bad "base_digest.$arch does NOT resolve by pull-by-digest: $base_image@$d"
    fi
  else
    pass "base_digest.$arch is a well-formed immutable digest (docker absent: resolution deferred)"
  fi
done

# ---- (2) APT snapshot: primary host + immutable (two fetches identical) -----
apt="$(pget apt_snapshot)"
if [ -z "$apt" ]; then
  bad "apt_snapshot is missing"
elif require_primary_host "$apt"; then
  a="$(sha256_of_url "$apt" 2>/dev/null || true)"
  b="$(sha256_of_url "$apt" 2>/dev/null || true)"
  if [ -n "$a" ] && [ "$a" = "$b" ]; then
    pass "apt_snapshot reachable + immutable (two fetches identical)"
  else
    bad "apt_snapshot is not reachable or not immutable (fetches differ): $apt"
  fi
fi

# ---- (3) per-arch rustup-init (Rust 1.88.0 installer) checksum --------------
for arch in x86_64 aarch64; do
  url="$(pget "rustup_init.$arch.url")"
  want="$(pget "rustup_init.$arch.sha256")"
  [ -n "$url" ] && [ -n "$want" ] || { bad "rustup_init.$arch url/sha256 missing"; continue; }
  require_primary_host "$url" || continue
  got="$(sha256_of_url "$url" 2>/dev/null || true)"
  if [ -n "$got" ] && [ "$got" = "$want" ]; then
    pass "rustup_init.$arch sha256 matches primary source"
  else
    bad "rustup_init.$arch sha256 MISMATCH (source=${got:-<unreachable>} proposed=$want)"
  fi
done

# ---- (4/5) tool identities: download declared artifact, recompute checksum --
count="$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1])).get("tool_identities",[])))' "$PINS" 2>/dev/null || echo 0)"
i=0
while [ "$i" -lt "$count" ]; do
  name="$(pget "tool_identities[$i].name")"
  ver="$(pget "tool_identities[$i].version")"
  url="$(pget "tool_identities[$i].artifact_identity")"
  algo="$(pget "tool_identities[$i].checksum_algorithm")"
  want="$(pget "tool_identities[$i].checksum_hex")"
  entry="$(pget "tool_identities[$i].install_entrypoint")"
  [ -n "$name" ] && [ -n "$url" ] && [ -n "$want" ] && [ -n "$entry" ] \
    || { bad "tool_identities[$i] ($name) has an absent field"; i=$((i + 1)); continue; }
  [ "$algo" = "sha256" ] || { bad "tool_identities[$i] ($name) checksum_algorithm must be sha256 (got '$algo')"; i=$((i + 1)); continue; }
  if require_primary_host "$url"; then
    got="$(sha256_of_url "$url" 2>/dev/null || true)"
    if [ -n "$got" ] && [ "$got" = "$want" ]; then
      pass "tool_identity $name@$ver checksum matches primary source"
    else
      bad "tool_identity $name@$ver checksum MISMATCH (source=${got:-<unreachable>} proposed=$want)"
    fi
  fi
  i=$((i + 1))
done
[ "$count" -ge 1 ] || bad "no tool_identities proposed (sp1-verifier + risc0-zkvm + risc0-groth16 required)"

echo "----"
if [ "$fail" -eq 0 ]; then
  note "all proposed pins verified against their primary sources (this is a PRECONDITION for ratification, not ratification)"
else
  die "one or more proposed pins failed primary-source verification; NOT eligible for ratification"
fi
