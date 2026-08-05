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
#   * each prover archive is DOWNLOADED and independently verified through the single
#     verified-extraction implementation (provision_prover_toolchain.sh): whole-archive
#     sha256, safe complete enumeration, complete member set, and every member's byte-size +
#     sha256 — and its archive_sha256 is cross-bound to the primary-source-verified
#     tool_identity checksum for the same url. member_sha256/archive_sha256 no longer rely on
#     a shape check plus in-image trust; they now have an independently verified duplicate.
#
# Usage: verify_pins.sh <proposed-pins.json>
# Requires: python3, curl, a sha256 tool (sha256sum/shasum), tar (cargo-audit .crate lock
# extraction + prover archive member extraction), docker (base index resolution).
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
# The Stage-2 supply-chain auditor the producer pins (see docs/b0-pre/venue/PIN-PROPOSAL.md).
REQUIRED_CARGO_AUDIT_VERSION="0.22.2"
# The canonical RustSec advisory database the Stage-2 audit runs against (READ-ONLY, pinned).
ADVISORY_DB_REPO="https://github.com/rustsec/advisory-db"
# The SP1 v6.3.1 release short commit that cargo-prove's arch-specific version output must carry.
SP1_PROVER_RELEASE_COMMIT="8252c29"
# The transcription-error r0vm member SHA the venue explicitly forbade — must never be pinned.
FORBIDDEN_R0VM_MEMBER_SHA256="36c01a65bb2ded5bd1f8f92cc487e6ffaeb1e95ec05850c983081a0f716b515b"

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
# is_bare_sha256 is defined in lib.sh (shared with the verified-extraction mechanism).

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

# ---- (6) cargo-audit: version + crate sha256 (primary source) + packaged Cargo.lock -----
# The Stage-2 auditor is pinned to an EXACT crates.io release. The strong primary-source
# binding is the .crate file's sha256 re-derived from static.crates.io; the packaged
# Cargo.lock sha256 (extracted from that same verified tarball) additionally pins the
# auditor's own dependency graph. source_commit is a format-checked provenance field (the
# upstream tag the release was cut from); it is not itself fetched here.
ca_version="$(pget cargo_audit.version)"
ca_crate_sha="$(pget cargo_audit.crate_sha256)"
ca_commit="$(pget cargo_audit.source_commit)"
ca_lock_sha="$(pget cargo_audit.packaged_lock_sha256)"
if [ -z "$ca_version" ] || [ -z "$ca_crate_sha" ] || [ -z "$ca_commit" ] || [ -z "$ca_lock_sha" ]; then
  bad "cargo_audit block incomplete (need version / crate_sha256 / source_commit / packaged_lock_sha256)"
else
  if [ "$ca_version" != "$REQUIRED_CARGO_AUDIT_VERSION" ]; then
    bad "cargo_audit.version is '$ca_version'; the producer pins cargo-audit $REQUIRED_CARGO_AUDIT_VERSION"
  fi
  is_bare_sha256 "$ca_crate_sha" || bad "cargo_audit.crate_sha256 is not a bare 64-hex sha256: $ca_crate_sha"
  is_bare_sha256 "$ca_lock_sha"  || bad "cargo_audit.packaged_lock_sha256 is not a bare 64-hex sha256: $ca_lock_sha"
  printf '%s' "$ca_commit" | grep -Eq '^[0-9a-f]{40}$' || bad "cargo_audit.source_commit is not a 40-hex commit: $ca_commit"
  if is_bare_sha256 "$ca_crate_sha" && is_bare_sha256 "$ca_lock_sha"; then
    crate_url="https://static.crates.io/crates/cargo-audit/cargo-audit-$ca_version.crate"
    tmpcrate="$(mktemp)"
    if ! curl -fsSL --max-redirs 5 --proto '=https' "$crate_url" -o "$tmpcrate"; then
      bad "cargo-audit .crate not reachable at its primary source: $crate_url"
    else
      got_crate="$(sha256_hex_stdin < "$tmpcrate")"
      if [ "$got_crate" = "$ca_crate_sha" ]; then
        pass "cargo-audit $ca_version .crate sha256 matches primary source (static.crates.io)"
      else
        bad "cargo-audit .crate sha256 MISMATCH (source=$got_crate pinned=$ca_crate_sha)"
      fi
      # Extract ONLY the packaged Cargo.lock from the verified tarball and hash it. A crate
      # whose sha256 matched but whose lock differs cannot occur (the tarball is immutable);
      # this binds the exact dependency graph the auditor itself was built against.
      got_lock="$(tar -xzOf "$tmpcrate" "cargo-audit-$ca_version/Cargo.lock" 2>/dev/null | sha256_hex_stdin || true)"
      if [ -z "$got_lock" ]; then
        bad "could not extract cargo-audit-$ca_version/Cargo.lock from the .crate (packaged lock absent)"
      elif [ "$got_lock" = "$ca_lock_sha" ]; then
        pass "cargo-audit $ca_version packaged Cargo.lock sha256 matches the verified .crate"
      else
        bad "cargo-audit packaged Cargo.lock sha256 MISMATCH (crate=$got_lock pinned=$ca_lock_sha)"
      fi
    fi
    rm -f "$tmpcrate"
  fi
fi

# ---- (7) advisory-DB: repo + commit + tree (primary source) + content digest ------------
# The Stage-2 audit runs against a READ-ONLY checkout of the RustSec advisory-db at an EXACT
# commit. The primary-source binding re-derives the commit's TREE sha from the canonical
# GitHub repo (curl-only, no clone) and matches it to the pinned tree — so a swapped commit
# or a fabricated tree fails without fetching the whole history. content_blake3 is the
# canonical checkout digest (tags.rs ADVDB_CHECKOUT_TAG); it is format-checked here and
# re-derived in full at produce time by `venue-verify checkout-digest` over the mounted
# checkout (and reproduced by the independent reference in the validator test suite).
adv_repo="$(pget advisory_db.repo)"
adv_commit="$(pget advisory_db.commit)"
adv_tree="$(pget advisory_db.git_tree)"
adv_content="$(pget advisory_db.content_blake3)"
if [ -z "$adv_repo" ] || [ -z "$adv_commit" ] || [ -z "$adv_tree" ] || [ -z "$adv_content" ]; then
  bad "advisory_db block incomplete (need repo / commit / git_tree / content_blake3)"
else
  [ "$adv_repo" = "$ADVISORY_DB_REPO" ] || bad "advisory_db.repo is '$adv_repo'; the pinned canonical source is $ADVISORY_DB_REPO"
  printf '%s' "$adv_commit" | grep -Eq '^[0-9a-f]{40}$' || bad "advisory_db.commit is not a 40-hex commit: $adv_commit"
  printf '%s' "$adv_tree"   | grep -Eq '^[0-9a-f]{40}$' || bad "advisory_db.git_tree is not a 40-hex tree: $adv_tree"
  is_bare_sha256 "$adv_content" || bad "advisory_db.content_blake3 is not a bare 64-hex digest: $adv_content"
  if [ "$adv_repo" = "$ADVISORY_DB_REPO" ] \
     && printf '%s' "$adv_commit" | grep -Eq '^[0-9a-f]{40}$' \
     && printf '%s' "$adv_tree" | grep -Eq '^[0-9a-f]{40}$'; then
    # GitHub commits API returns the commit's tree sha; this binds commit -> tree from the
    # canonical repo using only curl (RFC-compliant; no working tree materialized here).
    api="https://api.github.com/repos/rustsec/advisory-db/commits/$adv_commit"
    api_tree="$(curl -fsSL --max-redirs 5 --proto '=https' -H 'Accept: application/vnd.github+json' "$api" 2>/dev/null \
                | python3 -c 'import json,sys
try: print(json.load(sys.stdin)["commit"]["tree"]["sha"])
except Exception: print("")' 2>/dev/null || true)"
    if [ -z "$api_tree" ]; then
      bad "advisory_db.commit $adv_commit not resolvable at the canonical GitHub repo (or API unreachable): $api"
    elif [ "$api_tree" = "$adv_tree" ]; then
      pass "advisory_db commit $adv_commit -> tree $adv_tree confirmed by the canonical repo (content_blake3 re-derived at produce time)"
    else
      bad "advisory_db.git_tree MISMATCH: pinned=$adv_tree but commit $adv_commit has tree $api_tree upstream"
    fi
  fi
fi

# ---- (8) prover archives: declarative member identities (cargo-prove x86+aarch64, cargo-risczero
# x86, r0vm x86). The archive members are content-verified IN-IMAGE by the staged provisioner
# (provision_prover_toolchain.sh) after extraction; here we validate the PIN SHAPE + coverage +
# the shared-archive / delivery / no-rzup / forbidden-transcription rules. No rzup anywhere.
pa_count="$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1])).get("prover_archives",[])))' "$PINS" 2>/dev/null || echo 0)"
if [ "$pa_count" -eq 0 ]; then
  bad "prover_archives is missing/empty (need cargo-prove x86_64+aarch64, cargo-risczero x86_64, r0vm x86_64)"
fi
seen_cp_x86=0; seen_cp_arm=0; seen_cr_x86=0; seen_r0_x86=0
risczero_archive_id=""; r0vm_archive_id=""
i=0
while [ "$i" -lt "$pa_count" ]; do
  a_name="$(pget "prover_archives[$i].archive_name")"
  a_arch="$(pget "prover_archives[$i].arch")"
  a_sha="$(pget "prover_archives[$i].archive_sha256")"
  case "$a_arch" in x86_64|aarch64) ;; *) bad "prover_archives[$i] arch must be x86_64|aarch64 (got '$a_arch')"; i=$((i+1)); continue ;; esac
  is_bare_sha256 "$a_sha" || bad "prover_archives[$i] ($a_name/$a_arch) archive_sha256 is not bare 64-hex: '$a_sha'"
  m_count="$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["prover_archives"]['"$i"'].get("members",[])))' "$PINS" 2>/dev/null || echo 0)"
  [ "$m_count" -ge 1 ] || bad "prover_archives[$i] ($a_name/$a_arch) has no members"
  j=0
  while [ "$j" -lt "$m_count" ]; do
    exe="$(pget "prover_archives[$i].members[$j].executable_name")"
    msha="$(pget "prover_archives[$i].members[$j].member_sha256")"
    msize="$(pget "prover_archives[$i].members[$j].member_size_bytes")"
    vargv="$(pget "prover_archives[$i].members[$j].version_argv")"
    vout="$(pget "prover_archives[$i].members[$j].version_output")"
    relc="$(pget "prover_archives[$i].members[$j].expected_release_commit")"
    deliv="$(pget "prover_archives[$i].members[$j].delivery")"
    [ "$exe" = "rzup" ] && bad "prover_archives[$i] declares an rzup member (rzup is never used)"
    [ -n "$exe" ] || bad "prover_archives[$i].members[$j] executable_name empty"
    is_bare_sha256 "$msha" || bad "prover_archives[$i] ($exe) member_sha256 is not bare 64-hex: '$msha'"
    printf '%s' "$msize" | grep -Eq '^[1-9][0-9]*$' || bad "prover_archives[$i] ($exe) member_size_bytes must be a positive integer: '$msize'"
    [ -n "$vargv" ] || bad "prover_archives[$i] ($exe) version_argv empty"
    printf '%s' "$vargv" | grep -Eq "(^| )$exe( |$)|^cargo " || bad "prover_archives[$i] version_argv does not name $exe: '$vargv'"
    [ -n "$vout" ] || bad "prover_archives[$i] ($exe) version_output empty"
    if [ -n "$relc" ]; then
      grep <<<"$vout" -qF "$relc" || bad "prover_archives[$i] ($exe) version_output lacks the expected release identity '$relc'"
    fi
    # the transcription-error r0vm value must never be pinned.
    [ "$msha" = "$FORBIDDEN_R0VM_MEMBER_SHA256" ] && bad "prover_archives[$i] ($exe) pins the FORBIDDEN r0vm transcription value"
    case "$exe/$deliv" in
      cargo-prove/isolated-path|cargo-risczero/isolated-path|r0vm/risc0-server-path) ;;
      cargo-*/isolated-path) bad "prover_archives[$i] cargo subcommand $exe must use isolated-path (got '$deliv')" ;;
      r0vm/*) bad "prover_archives[$i] r0vm must use risc0-server-path (got '$deliv')" ;;
      *) bad "prover_archives[$i] ($exe) invalid delivery '$deliv'" ;;
    esac
    # RISC Zero executables are x86_64 only.
    case "$exe/$a_arch" in cargo-risczero/aarch64|r0vm/aarch64) bad "prover_archives[$i] $exe on aarch64 (RISC Zero is x86_64-only, VENUE.md §2)" ;; esac
    case "$exe/$a_arch" in
      cargo-prove/x86_64) seen_cp_x86=1 ;;
      cargo-prove/aarch64) seen_cp_arm=1 ;;
      cargo-risczero/x86_64) seen_cr_x86=1; risczero_archive_id="$a_name/$a_arch/$a_sha" ;;
      r0vm/x86_64) seen_r0_x86=1; r0vm_archive_id="$a_name/$a_arch/$a_sha" ;;
    esac
    j=$((j+1))
  done
  i=$((i+1))
done
[ "$seen_cp_x86" = 1 ] || bad "prover_archives: no cargo-prove for x86_64"
[ "$seen_cp_arm" = 1 ] || bad "prover_archives: no cargo-prove for aarch64"
[ "$seen_cr_x86" = 1 ] || bad "prover_archives: no cargo-risczero for x86_64"
[ "$seen_r0_x86" = 1 ] || bad "prover_archives: no r0vm for x86_64"
# cargo-risczero + r0vm MUST be members of ONE shared archive identity.
if [ "$seen_cr_x86" = 1 ] && [ "$seen_r0_x86" = 1 ]; then
  [ "$risczero_archive_id" = "$r0vm_archive_id" ] \
    && pass "prover_archives: cargo-prove x86_64+aarch64, cargo-risczero x86_64, r0vm x86_64 (cargo-risczero + r0vm share one archive); shapes + delivery + no-rzup verified" \
    || bad "prover_archives: cargo-risczero ($risczero_archive_id) and r0vm ($r0vm_archive_id) are NOT the same shared archive"
fi

# ---- (5b) prover archive AUTHORITY: download each immutable archive and INDEPENDENTLY verify it
# through the SINGLE verified-extraction implementation (provision_prover_toolchain.sh): whole-
# archive sha256 BEFORE reading, safe COMPLETE enumeration, complete-member-set (no undeclared
# member, no missing member), and each declared member's byte-size + sha256. Also cross-bind each
# archive_sha256 to the independently primary-source-verified tool_identity checksum for the SAME
# url (the risc0 archive is shared across risc0-zkvm + risc0-groth16). This closes the
# archive_sha256/member_sha256 authority gap: before this, those pins had NO independently verified
# duplicate — they were shape-checked here, then trusted to the in-image extractor at build time.
if [ "$pa_count" -gt 0 ]; then
  ptmp="$(mktemp -d)"
  i=0
  while [ "$i" -lt "$pa_count" ]; do
    a_name="$(pget "prover_archives[$i].archive_name")"
    a_arch="$(pget "prover_archives[$i].arch")"
    a_url="$(pget "prover_archives[$i].archive_url")"
    a_sha="$(pget "prover_archives[$i].archive_sha256")"
    if [ -z "$a_url" ]; then bad "prover_archives[$i] ($a_name/$a_arch) archive_url missing — cannot independently verify"; i=$((i + 1)); continue; fi
    # (a) cross-bind archive_sha256 to the tool_identity checksum for the SAME url (independent duplicate)
    ti_sha="$(python3 - "$PINS" "$a_url" <<'PY' 2>/dev/null || true
import json, sys
d = json.load(open(sys.argv[1])); url = sys.argv[2]
hits = {t.get("checksum_hex", "") for t in d.get("tool_identities", []) if t.get("artifact_identity") == url}
print(next(iter(hits)) if len(hits) == 1 else "")
PY
)"
    if [ -z "$ti_sha" ]; then
      bad "prover_archives[$i] ($a_name/$a_arch) archive_url has no unique tool_identity cross-binding: $a_url"; i=$((i + 1)); continue
    elif [ "$ti_sha" != "$a_sha" ]; then
      bad "prover_archives[$i] ($a_name/$a_arch) archive_sha256 ($a_sha) != tool_identity checksum ($ti_sha) for the same url"; i=$((i + 1)); continue
    fi
    # (b) build the COMPLETE member spec set (member_path:sha256:size:delivery) from the pins
    specs=""
    m_count="$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["prover_archives"]['"$i"'].get("members",[])))' "$PINS" 2>/dev/null || echo 0)"
    spec_ok=1
    j=0
    while [ "$j" -lt "$m_count" ]; do
      mp="$(pget "prover_archives[$i].members[$j].member_path")"
      ms="$(pget "prover_archives[$i].members[$j].member_sha256")"
      mz="$(pget "prover_archives[$i].members[$j].member_size_bytes")"
      md="$(pget "prover_archives[$i].members[$j].delivery")"
      case "$md" in
        isolated-path)    dv="isolated" ;;
        risc0-server-path) dv="risc0server" ;;
        *) bad "prover_archives[$i].members[$j] ($mp) unknown delivery '$md'"; spec_ok=0; dv="isolated" ;;
      esac
      specs="$specs $mp:$ms:$mz:$dv"
      j=$((j + 1))
    done
    if [ "$m_count" -lt 1 ] || [ "$spec_ok" -ne 1 ]; then bad "prover_archives[$i] ($a_name/$a_arch) has no usable member spec set"; i=$((i + 1)); continue; fi
    # (c) download + INDEPENDENTLY verify via the single verified-extraction implementation (temp
    # placement, discarded). provision_prover_toolchain.sh `die`s (exit 4) on ANY mismatch; run as a
    # child process so its failure is captured as a non-zero rc here rather than aborting verify_pins.
    af="$ptmp/a$i.tgz"
    if ! curl -fsSL --max-redirs 5 "$a_url" -o "$af"; then bad "prover_archives[$i] ($a_name/$a_arch) archive not reachable: $a_url"; i=$((i + 1)); continue; fi
    # shellcheck disable=SC2086  # $specs is an intentional word-split list of member specs
    if bash "$HERE/provision_prover_toolchain.sh" "$af" "$a_sha" "$ptmp/iso$i" "$ptmp/r0$i" $specs >/dev/null 2>"$ptmp/e$i"; then
      pass "prover_archives[$i] ($a_name/$a_arch) archive sha256 + $m_count member(s) independently verified via the single verified-extraction implementation; archive cross-bound to the tool_identity checksum"
    else
      bad "prover_archives[$i] ($a_name/$a_arch) independent archive/member verification FAILED: $(head -1 "$ptmp/e$i" 2>/dev/null)"
    fi
    rm -f "$af"
    i=$((i + 1))
  done
  rm -rf "$ptmp"
fi

# ---- v4 capability blocks: guest toolchains + Groth16 circuit + OCI backends -----------------
# When the proposal declares the v4 contract, verify its three Stage-5 capability blocks against
# the FROZEN identity set via the typed pin-contract checker (the same evaluate_contract the venue
# runs). Primary-source re-derivation of the multi-GB circuit / ~100MB toolchain archives is NOT
# performed here — those are owner content pins whose AUTHORITY is the independently-reproduced
# provisioned-tree/runtime-tree BLAKE3 digests frozen in the contract; this asserts the declared
# identities equal that reproduced set and fail-closes on any drift.
cv="$(pget contract_version)"
if [ "$cv" = "v4" ]; then
  VAL="$HERE/../../b0-pre-validator/Cargo.toml"
  if [ -n "${VENUE_VERIFY_BIN:-}" ] && [ -x "${VENUE_VERIFY_BIN}" ]; then
    if "$VENUE_VERIFY_BIN" pin-contract-check "$PINS" >/dev/null 2>&1; then
      pass "v4 capability blocks: guest toolchains + Groth16 circuit runtime tree + OCI backends match the frozen Stage-5 identity set (pin-contract-check)"
    else bad "v4 capability blocks failed the typed pin-contract check (venue-verify pin-contract-check)"; fi
  elif command -v cargo >/dev/null 2>&1; then
    if cargo run --quiet --locked --manifest-path "$VAL" --bin venue-verify -- pin-contract-check "$PINS" >/dev/null 2>&1; then
      pass "v4 capability blocks: guest toolchains + Groth16 circuit runtime tree + OCI backends match the frozen Stage-5 identity set (pin-contract-check)"
    else bad "v4 capability blocks failed the typed pin-contract check (venue-verify pin-contract-check)"; fi
  else
    bad "v4 contract declared but neither VENUE_VERIFY_BIN nor cargo is available to run pin-contract-check"
  fi
fi

echo "----"
if [ "$fail" -eq 0 ]; then
  note "all proposed pins verified against their primary sources (this is a PRECONDITION for ratification, not ratification)"
else
  die "one or more proposed pins failed primary-source verification; NOT eligible for ratification"
fi
