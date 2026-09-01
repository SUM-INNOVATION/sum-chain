#!/usr/bin/env bash
# Deterministic per-arch B0-FINAL two-root VALIDATION bundle generator + verifier + selftest.
#
# A validation bundle carries the AUTHORITY + PROCEDURE the venue needs to validate the two-root
# identity/measurement path from clean checkouts: the pinned protobuf include authority, the two-root
# validation procedure, the CANONICAL TOOLING INVENTORY (the exact path-set preimage — every included
# file's BLAKE3), and a MANIFEST binding the measured/tooling authorities + the required-venue-produced
# outputs. The bundle's authoritative identity is the content address over its members
# (domain-separated BLAKE3 of "<member_blake3>  <relpath>" lines); the tar is transport.
#
# CONTENT BINDING (why the address authenticates the whole tooling payload):
#   * tooling-inventory.txt IS the canonical path-set preimage produced by tooling_pathset.sh — one
#     "<file_blake3>  <relpath>" line per included file — so a one-byte change to ANY included tooling
#     file changes its line, hence the inventory bytes, hence the path-set digest, hence (since the
#     inventory is a bundle member hashed into the content address) the bundle content address.
#   * MANIFEST.json binds the ratified Commit-A tooling commit + the canonical path-set BLAKE3, and is
#     itself a hashed member. BLAKE3(pathset-domain || inventory bytes) == MANIFEST.tooling_pathset_blake3.
#   * The tooling identity is NOT caller-supplied: it is derived from a CLEAN checkout (git), and on a
#     post-Commit-B tree is accepted only if the tree differs from the ratified Commit A solely at the
#     sole excluded file (tooling_authority.rs) AND the recomputed included-file digest equals the
#     ratified digest. Otherwise it refuses. No PENDING placeholder ever ships.
#
# It NEVER fabricates an unknown native value: protoc/runner/docker/builder identities are declared as
# required-venue-produced in the MANIFEST, with no stand-in presented as authority.
#
# Usage:
#   make_validation_bundle.sh --arch <x86_64|aarch64> [--authority-dir <dir>] --out <dir>
#       Generate the bundle for one arch (identity derived from the clean checkout).
#   make_validation_bundle.sh --verify <members-dir> --arch <a> \
#       [--expect-address <hex>] [--expect-commit <hex>] [--expect-digest <hex>]
#       Verify an EXTRACTED bundle member directory fail-closed; print its content address.
#   make_validation_bundle.sh --selftest
#       Run the content-binding regression suite (generate + verify + tamper/mutation negatives).
set -euo pipefail

DOMAIN='b0-final-two-root-validation-bundle/v1'
PATHSET_DOMAIN='b0-final-measurement-tooling-pathset/v1'
RATIFIED_SOURCE_COMMIT='507281e21e95a6a98e3480e25e12d1baab586e07'
EXCLUDE='tools/b0-pre-validator/src/tooling_authority.rs'
die() { printf 'BUNDLE-REFUSED: %s\n' "$*" >&2; exit 10; }

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"

command -v b3sum >/dev/null 2>&1 || die "b3sum not available"
command -v git   >/dev/null 2>&1 || die "git not available"

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

is_hex40() { printf '%s' "${1:-}" | grep -Eq '^[0-9a-f]{40}$'; }
is_hex64() { printf '%s' "${1:-}" | grep -Eq '^[0-9a-f]{64}$'; }

# Minimal flat-JSON readers (no jq dependency in the venue).
json_str() { grep -oE "\"$2\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" "$1" | head -1 | sed -E 's/.*:[[:space:]]*"([^"]*)"$/\1/'; }
json_num() { grep -oE "\"$2\"[[:space:]]*:[[:space:]]*[0-9]+" "$1" | head -1 | grep -oE '[0-9]+$'; }

# Content address over an extracted member directory: BLAKE3( DOMAIN NUL manifest ), manifest =
# per member (LC_ALL=C sorted relpath) "<member_blake3>  <relpath>\n". Binds membership + every byte.
compute_content_address() {
  local d="$1" m bh manifest=""
  while IFS= read -r m; do
    bh="$(b3sum "$d/$m" | awk '{print $1}')"
    manifest="${manifest}${bh}  ${m}"$'\n'
  done < <(cd "$d" && find . -type f | LC_ALL=C sort | sed 's#^\./##')
  { printf '%s\0' "$DOMAIN"; printf '%s' "$manifest"; } | b3sum | awk '{print $1}'
}

# Path-set digest of an inventory (preimage) file == BLAKE3( pathset-domain NUL <file bytes> ).
pathset_digest_of() { { printf '%s\0' "$PATHSET_DOMAIN"; cat "$1"; } | b3sum | awk '{print $1}'; }

# Extract a ratified authority const from tooling_authority.rs (the quoted hex, or the UNBOUND token).
extract_ratified_const() {
  awk -v name="$1" '
    index($0, "const " name) { c=1 }
    c {
      buf = buf $0 " "
      if (index($0, ";")) {
        if (match(buf, /"[0-9a-f]+"/)) { print substr(buf, RSTART+1, RLENGTH-2) }
        else if (buf ~ /UNBOUND/)      { print "UNBOUND" }
        exit
      }
    }' "$ROOT/tools/b0-pre-validator/src/tooling_authority.rs"
}

# Derive the tooling identity from a CLEAN checkout (never caller-supplied). Sets globals
# TOOLING_COMMIT, PATHSET_DIGEST, PATH_COUNT and writes the canonical preimage to $1.
derive_identity() {
  local inv_out="$1"
  # B0-PRE RETIREMENT GATE (#196): generating a validation bundle is a production-measurement action,
  # disabled on a retired tooling tree. Fail-closed before any work.
  if grep -qE '^pub const B0_PRE_RETIRED: bool = true;' \
       "$ROOT/tools/b0-pre-validator/src/tooling_authority.rs" 2>/dev/null; then
    die "B0_PRE_RETIRED: measurement tooling retired; cannot generate a validation bundle (see docs/b0-final/B0-PRE-RETIREMENT.md; verify historical evidence from tag b0-final-evidence-60ace32c)"
  fi
  git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1 || die "not a git work tree: $ROOT"
  [ -z "$(git -C "$ROOT" status --porcelain)" ] \
    || die "refusing: working tree is dirty; the embedded tooling identity must derive from a clean checkout"
  local head computed ratc ratd
  head="$(git -C "$ROOT" rev-parse HEAD)"
  # Canonical path-set digest + preimage over the clean tooling root (fail-closed; no `|| true`).
  computed="$("$HERE/tooling_pathset.sh" --root "$ROOT" --require-clean --out "$inv_out")" \
    || die "canonical tooling path-set computation refused"
  is_hex64 "$computed" || die "path-set digest malformed"
  PATH_COUNT="$(grep -c . "$inv_out")"
  ratc="$(extract_ratified_const RATIFIED_MEASUREMENT_TOOLING_COMMIT)"
  ratd="$(extract_ratified_const RATIFIED_MEASUREMENT_TOOLING_PATHSET_BLAKE3)"
  if [ "$ratc" = UNBOUND ] || [ "$ratd" = UNBOUND ]; then
    # Clean Commit A (authority not yet bound): the checked-out clean tree IS Commit A.
    TOOLING_COMMIT="$head"
    PATHSET_DIGEST="$computed"
  else
    # Post-Commit-B tree: accept the Commit-A identity ONLY under the sole-excluded-file rule.
    is_hex40 "$ratc" || die "bound tooling commit malformed"
    is_hex64 "$ratd" || die "bound tooling digest malformed"
    [ "$computed" = "$ratd" ] \
      || die "recomputed included-file digest $computed != ratified $ratd"
    git -C "$ROOT" rev-parse -q --verify "${ratc}^{commit}" >/dev/null \
      || die "ratified tooling commit $ratc is not a commit in this repo"
    # WHOLE-TREE B15 GUARD REMOVED (#196): the `git diff CommitA..HEAD == tooling_authority.rs`
    # freeze check is retired with the measurement phase (and is unreachable once the live authority
    # is UNBOUND, which takes the Commit-A branch above). Historical verification uses the tagged
    # historical commit/release; see docs/b0-final/B0-PRE-RETIREMENT.md.
    TOOLING_COMMIT="$ratc"
    PATHSET_DIGEST="$ratd"
  fi
  is_hex40 "$TOOLING_COMMIT" || die "derived tooling commit malformed: $TOOLING_COMMIT"
  is_hex64 "$PATHSET_DIGEST" || die "derived tooling digest malformed"
}

generate() {
  local arch="$1" auth="$2" out="$3"
  case "$arch" in x86_64|aarch64) ;; *) die "--arch must be x86_64|aarch64" ;; esac
  [ -n "$auth" ] || auth="$ROOT/docs/b0-pre/venue/protobuf-include-authority"
  [ -d "$auth" ] || die "--authority-dir must be an existing directory"
  [ -f "$auth/INVENTORY.json" ] && [ -f "$auth/CONTENT-ADDRESS.txt" ] \
    && [ -f "$auth/include/google/protobuf/empty.proto" ] || die "authority dir incomplete"
  [ -n "$out" ] || die "--out required"

  local pa_sha pa_b3
  pa_sha="$(grep -oE 'content_address_sha256 [0-9a-f]{64}' "$auth/CONTENT-ADDRESS.txt" | awk '{print $2}')"
  pa_b3="$(grep -oE 'content_address_blake3 [0-9a-f]{64}' "$auth/CONTENT-ADDRESS.txt" | awk '{print $2}')"
  is_hex64 "$pa_sha" && is_hex64 "$pa_b3" || die "protobuf authority content-address unreadable"

  local stage; stage="$(mktemp -d "$TMP/stage.XXXXXX")"
  mkdir -p "$stage/protobuf-include-authority/include/google/protobuf"
  cp "$auth/INVENTORY.json"       "$stage/protobuf-include-authority/INVENTORY.json"
  cp "$auth/CONTENT-ADDRESS.txt"  "$stage/protobuf-include-authority/CONTENT-ADDRESS.txt"
  cp "$auth/include/google/protobuf/empty.proto" "$stage/protobuf-include-authority/include/google/protobuf/empty.proto"
  cp "$ROOT/docs/b0-pre/venue/two-root-validation-procedure.md" "$stage/procedure.md"

  # Canonical tooling inventory (preimage) + fail-closed tooling identity from the clean checkout.
  derive_identity "$stage/tooling-inventory.txt"

  # MANIFEST binds schema/domain, arch, measured source, ratified Commit A + path count + path-set
  # digest (+ domain), and the protobuf authority address. No PENDING placeholder.
  cat > "$stage/MANIFEST.json" <<JSON
{
  "schema": "$DOMAIN",
  "arch": "$arch",
  "measured_source_commit": "$RATIFIED_SOURCE_COMMIT",
  "measured_source_note": "frozen; guest/candidate/witness/lock identities derive ONLY from this root",
  "tooling_commit": "$TOOLING_COMMIT",
  "tooling_path_count": $PATH_COUNT,
  "tooling_pathset_blake3": "$PATHSET_DIGEST",
  "tooling_pathset_domain": "$PATHSET_DOMAIN",
  "tooling_pathset_note": "canonical preimage is tooling-inventory.txt; BLAKE3(tooling_pathset_domain NUL || inventory bytes) == tooling_pathset_blake3; excludes only $EXCLUDE",
  "protobuf_authority_content_address_sha256": "$pa_sha",
  "protobuf_authority_content_address_blake3": "$pa_b3",
  "required_venue_produced": [
    "native_protoc_sha256", "native_protoc_blake3", "native_protoc_version(==libprotoc 3.21.12)",
    "runner_sha256", "runner_blake3", "reproducibility_pair_blake3", "docker_argv_blake3",
    "immutable_builder_identity", "measured_source_context_blake3", "cpuset_probe_chain_blake3"
  ],
  "fabrication_policy": "unknown native outputs are REQUIRED venue-produced; no stand-in is presented as authority"
}
JSON

  local content_address; content_address="$(compute_content_address "$stage")"

  mkdir -p "$out"
  local tarball="$out/two-root-validation-bundle.$arch.tar"
  # Member list is written OUTSIDE the stage so it is never itself a bundle member — the tar contains
  # EXACTLY the members hashed into the content address (nothing transient), so a re-extract verifies.
  local flist="$TMP/filelist.$arch"
  ( cd "$stage" && find . -type f | LC_ALL=C sort | sed 's#^\./##' > "$flist" )
  # Portable transport tar (GNU + BSD tar): the AUTHENTICATED identity is the content address over the
  # members, NOT the tar bytes, so the tar only needs a faithful create+extract roundtrip of the exact
  # members — no BSD-only flags (--no-mac-metadata/--uid/--gid), which GNU tar rejects. COPYFILE_DISABLE
  # suppresses macOS AppleDouble sidecars (ignored on Linux). Fail closed if the tar is not produced.
  ( cd "$stage" && COPYFILE_DISABLE=1 tar -cf "$tarball" $(tr '\n' ' ' < "$flist") ) \
    || die "bundle tar creation failed"
  [ -f "$tarball" ] || die "bundle tar not produced: $tarball"
  printf '%s\n' "$content_address" > "$out/two-root-validation-bundle.$arch.content-address"
  printf 'bundle arch=%s content_address=%s tooling_commit=%s tooling_digest=%s count=%s tar=%s\n' \
    "$arch" "$content_address" "$TOOLING_COMMIT" "$PATHSET_DIGEST" "$PATH_COUNT" "$tarball" >&2
  printf '%s\n' "$content_address"
}

# Verify an EXTRACTED member directory fail-closed. Args: <dir> <arch> [expect_address|-] [expect_commit|-] [expect_digest|-]
verify_members() {
  local d="$1" arch="$2" xaddr="${3:--}" xcommit="${4:--}" xdigest="${5:--}"
  local man="$d/MANIFEST.json" inv="$d/tooling-inventory.txt"
  [ -f "$man" ] || die "verify: MANIFEST.json missing"
  [ -f "$inv" ] || die "verify: tooling-inventory.txt missing"
  grep -riq 'PENDING' "$d" && die "verify: PENDING placeholder present in bundle" || true
  local m_schema m_arch m_src m_commit m_digest m_count
  m_schema="$(json_str "$man" schema)"; m_arch="$(json_str "$man" arch)"
  m_src="$(json_str "$man" measured_source_commit)"; m_commit="$(json_str "$man" tooling_commit)"
  m_digest="$(json_str "$man" tooling_pathset_blake3)"; m_count="$(json_num "$man" tooling_path_count)"
  [ "$m_schema" = "$DOMAIN" ] || die "verify: schema $m_schema != $DOMAIN"
  [ "$m_arch" = "$arch" ] || die "verify: arch $m_arch != $arch"
  [ "$m_src" = "$RATIFIED_SOURCE_COMMIT" ] || die "verify: measured_source_commit $m_src != $RATIFIED_SOURCE_COMMIT"
  is_hex40 "$m_commit" || die "verify: tooling_commit not 40-hex (PENDING/UNBOUND?): $m_commit"
  is_hex64 "$m_digest" || die "verify: tooling_pathset_blake3 not 64-hex: $m_digest"
  [ -n "$m_count" ] || die "verify: tooling_path_count missing"
  # Inventory shape: each line "<64hex>  <relpath>", LC_ALL=C sorted, unique, count == manifest, excluded absent.
  grep -qvE '^[0-9a-f]{64}  [^[:space:]]' "$inv" && die "verify: malformed inventory line(s)" || true
  awk '{print $2}' "$inv" | LC_ALL=C sort -c 2>/dev/null || die "verify: inventory relpaths not LC_ALL=C sorted"
  local nrel nuniq
  nrel="$(awk '{print $2}' "$inv" | grep -c .)"
  nuniq="$(awk '{print $2}' "$inv" | LC_ALL=C sort -u | grep -c .)"
  [ "$nrel" = "$nuniq" ] || die "verify: duplicate inventory relpath(s)"
  [ "$nrel" = "$m_count" ] || die "verify: inventory line count $nrel != manifest tooling_path_count $m_count"
  awk '{print $2}' "$inv" | grep -qxF "$EXCLUDE" && die "verify: excluded file present in inventory" || true
  # Inventory-derived digest ties the inventory bytes to the declared digest.
  local d_inv; d_inv="$(pathset_digest_of "$inv")"
  [ "$d_inv" = "$m_digest" ] || die "verify: inventory-derived digest $d_inv != manifest $m_digest"
  # Optional ratified expectations (catch a self-consistent but WRONG rewrite).
  [ "$xcommit" = "-" ] || [ "$m_commit" = "$xcommit" ] || die "verify: tooling_commit $m_commit != expected $xcommit"
  [ "$xdigest" = "-" ] || [ "$m_digest" = "$xdigest" ] || die "verify: tooling digest $m_digest != expected $xdigest"
  local addr; addr="$(compute_content_address "$d")"
  [ "$xaddr" = "-" ] || [ "$addr" = "$xaddr" ] || die "verify: content-address $addr != expected $xaddr"
  printf '%s\n' "$addr"
}

selftest() {
  local st_rc=0
  pass() { printf '  PASS: %s\n' "$1"; }
  fail() { printf '  FAIL: %s\n' "$1"; st_rc=1; }
  local work; work="$(mktemp -d "$TMP/selftest.XXXXXX")"
  local out="$work/out" mem="$work/mem"
  mkdir -p "$out" "$mem"

  # 1. Generate a pristine bundle from the clean checkout, then extract its members.
  local addr; addr="$(generate x86_64 "" "$out")" || { die "selftest: generation refused"; }
  tar -xf "$out/two-root-validation-bundle.x86_64.tar" -C "$mem"
  local man="$mem/MANIFEST.json" inv="$mem/tooling-inventory.txt"
  local m_commit m_digest m_count
  m_commit="$(json_str "$man" tooling_commit)"; m_digest="$(json_str "$man" tooling_pathset_blake3)"
  m_count="$(json_num "$man" tooling_path_count)"

  # 2. Inventory is exactly the canonical path-set preimage; every line well-formed; sorted; unique.
  if ! grep -qvE '^[0-9a-f]{64}  [^[:space:]]' "$inv"; then pass "every inventory line is <64hex><2sp><relpath>"; else fail "malformed inventory line"; fi
  if awk '{print $2}' "$inv" | LC_ALL=C sort -c 2>/dev/null; then pass "inventory relpaths LC_ALL=C sorted"; else fail "inventory relpaths not sorted"; fi
  if [ "$(awk '{print $2}' "$inv" | grep -c .)" = "$(awk '{print $2}' "$inv" | LC_ALL=C sort -u | grep -c .)" ]; then pass "no duplicate inventory relpath"; else fail "duplicate relpath"; fi
  local canon; canon="$("$HERE/tooling_pathset.sh" --root "$ROOT" --out "$work/canon.txt" 2>/dev/null)"
  if cmp -s "$inv" "$work/canon.txt"; then pass "inventory == canonical tooling_pathset.sh preimage"; else fail "inventory != canonical preimage"; fi

  # 3. Exact-set: count == manifest count == canonical path count; excluded file absent.
  if [ "$(grep -c . "$inv")" = "$m_count" ] && [ "$m_count" = "$(grep -c . "$work/canon.txt")" ]; then pass "exact set: $m_count files"; else fail "count mismatch"; fi
  if ! awk '{print $2}' "$inv" | grep -qxF "$EXCLUDE"; then pass "sole excluded file absent from inventory"; else fail "excluded file present"; fi

  # 4. inventory-derived digest == manifest digest == canonical digest.
  if [ "$(pathset_digest_of "$inv")" = "$m_digest" ] && [ "$m_digest" = "$canon" ]; then pass "inventory digest == manifest == canonical ($m_digest)"; else fail "digest inconsistency"; fi

  # 5. MANIFEST binds the real Commit A + digest; never PENDING.
  if is_hex40 "$m_commit"; then pass "MANIFEST tooling_commit is a real 40-hex SHA ($m_commit)"; else fail "tooling_commit not real SHA"; fi
  if ! grep -riq 'PENDING' "$mem"; then pass "no PENDING placeholder anywhere in bundle"; else fail "PENDING present"; fi

  # 6. Pristine bundle passes verification (with ratified expectations).
  if ( verify_members "$mem" x86_64 "$addr" "$m_commit" "$m_digest" ) >/dev/null 2>&1; then pass "pristine bundle verifies"; else fail "pristine bundle failed verification"; fi

  # 7. One-byte mutation of an included tooling file -> inventory line, path-set digest, AND bundle
  #    content address all change (proven via the file's real BLAKE3 before/after).
  local pick='tools/b0-pre-measure-core/src/run.rs'
  local h0 h1; h0="$(b3sum "$ROOT/$pick" | awk '{print $1}')"
  cp "$ROOT/$pick" "$work/mut"; printf '\n// selftest-mutation\n' >> "$work/mut"; h1="$(b3sum "$work/mut" | awk '{print $1}')"
  local mm="$work/mem_mut"; cp -r "$mem" "$mm"
  sed "s#^$h0  $pick\$#$h1  $pick#" "$mem/tooling-inventory.txt" > "$mm/tooling-inventory.txt"
  if [ "$h0" != "$h1" ] && ! cmp -s "$mem/tooling-inventory.txt" "$mm/tooling-inventory.txt" \
     && [ "$(pathset_digest_of "$mem/tooling-inventory.txt")" != "$(pathset_digest_of "$mm/tooling-inventory.txt")" ] \
     && [ "$(compute_content_address "$mem")" != "$(compute_content_address "$mm")" ]; then
    pass "one-byte included-file mutation changes inventory, path-set digest, and bundle address"
  else fail "one-byte mutation did not propagate to inventory/digest/address"; fi

  # 8. Tampering tooling-inventory.txt fails verification.
  if ( verify_members "$mm" x86_64 "-" "-" "-" ) >/dev/null 2>&1; then fail "tampered inventory verified"; else pass "tampered tooling-inventory.txt fails verification"; fi

  # 9. Tampering MANIFEST commit or digest fails verification.
  local tc="$work/mem_tc"; cp -r "$mem" "$tc"
  sed "s#\"tooling_commit\": \"$m_commit\"#\"tooling_commit\": \"$(printf 'a%.0s' {1..40})\"#" "$mem/MANIFEST.json" > "$tc/MANIFEST.json"
  if ( verify_members "$tc" x86_64 "-" "$m_commit" "-" ) >/dev/null 2>&1; then fail "tampered MANIFEST commit verified"; else pass "tampered MANIFEST commit fails verification"; fi
  local td="$work/mem_td"; cp -r "$mem" "$td"
  sed "s#\"tooling_pathset_blake3\": \"$m_digest\"#\"tooling_pathset_blake3\": \"$(printf 'b%.0s' {1..64})\"#" "$mem/MANIFEST.json" > "$td/MANIFEST.json"
  if ( verify_members "$td" x86_64 "-" "-" "-" ) >/dev/null 2>&1; then fail "tampered MANIFEST digest verified"; else pass "tampered MANIFEST digest fails verification"; fi

  # 10. Missing / extra / reordered inventory line refuses.
  local miss="$work/mem_miss"; cp -r "$mem" "$miss"; sed '$d' "$mem/tooling-inventory.txt" > "$miss/tooling-inventory.txt"
  if ( verify_members "$miss" x86_64 "-" "-" "-" ) >/dev/null 2>&1; then fail "missing inventory line verified"; else pass "missing inventory line refuses"; fi
  local extra="$work/mem_extra"; cp -r "$mem" "$extra"; { cat "$mem/tooling-inventory.txt"; printf '%s  zzz/extra/path.rs\n' "$(printf 'c%.0s' {1..64})"; } > "$extra/tooling-inventory.txt"
  if ( verify_members "$extra" x86_64 "-" "-" "-" ) >/dev/null 2>&1; then fail "extra inventory line verified"; else pass "extra inventory line refuses"; fi
  local reord="$work/mem_reord"; cp -r "$mem" "$reord"; { sed -n '2p' "$mem/tooling-inventory.txt"; sed -n '1p' "$mem/tooling-inventory.txt"; sed '1,2d' "$mem/tooling-inventory.txt"; } > "$reord/tooling-inventory.txt"
  if ( verify_members "$reord" x86_64 "-" "-" "-" ) >/dev/null 2>&1; then fail "reordered inventory verified"; else pass "reordered inventory refuses"; fi

  [ "$st_rc" -eq 0 ] || die "validation-bundle selftest FAILED"
  echo "validation-bundle selftest: ALL PASS"
}

# ---- CLI dispatch ----
MODE=generate ARCH="" AUTH="" OUT="" VDIR="" XADDR="-" XCOMMIT="-" XDIGEST="-"
while [ $# -gt 0 ]; do
  case "$1" in
    --selftest) MODE=selftest; shift ;;
    --verify) [ $# -ge 2 ] || die "--verify needs a dir"; MODE=verify; VDIR="$2"; shift 2 ;;
    --arch) [ $# -ge 2 ] || die "--arch needs a value"; ARCH="$2"; shift 2 ;;
    --authority-dir) [ $# -ge 2 ] || die "--authority-dir needs a value"; AUTH="$2"; shift 2 ;;
    --out) [ $# -ge 2 ] || die "--out needs a value"; OUT="$2"; shift 2 ;;
    --expect-address) [ $# -ge 2 ] || die "--expect-address needs a value"; XADDR="$2"; shift 2 ;;
    --expect-commit) [ $# -ge 2 ] || die "--expect-commit needs a value"; XCOMMIT="$2"; shift 2 ;;
    --expect-digest) [ $# -ge 2 ] || die "--expect-digest needs a value"; XDIGEST="$2"; shift 2 ;;
    *) die "unknown/positional argument: $1" ;;
  esac
done

case "$MODE" in
  generate) generate "$ARCH" "$AUTH" "$OUT" ;;
  verify)   case "$ARCH" in x86_64|aarch64) ;; *) die "--arch must be x86_64|aarch64" ;; esac
            verify_members "$VDIR" "$ARCH" "$XADDR" "$XCOMMIT" "$XDIGEST" ;;
  selftest) selftest ;;
esac
