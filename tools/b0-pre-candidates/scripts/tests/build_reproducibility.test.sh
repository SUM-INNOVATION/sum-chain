#!/usr/bin/env bash
# Defect 1: two clean --no-cache builds must be byte/content-address identical. The
# EMPIRICAL two-build equality runs on the venue (and locally via
# oci_daemon_bridge.test.sh tier C). This test asserts the SOURCE-LEVEL determinism
# controls are present and the equality gate is NOT weakened:
#  - build_container.sh derives SOURCE_DATE_EPOCH from the ratified commit's committer
#    date and passes it + the exporter's rewrite-timestamp=true;
#  - the manifest-identity equality gate (m1==m2) is unchanged and still fatal;
#  - both Dockerfiles declare SOURCE_DATE_EPOCH and drop build-time-content (logs/caches)
#    IN-LAYER (so content, not just mtimes, is deterministic).
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS="$(cd "$HERE/.." && pwd)"
CONTAINERS="$(cd "$SCRIPTS/../containers" && pwd)"
set +e
fails=0
ok()  { printf 'ok    %s\n' "$1"; }
bad() { printf 'FAIL  %s\n' "$1" >&2; fails=$((fails + 1)); }
has() { grep -qF -- "$2" "$1"; }

BC="$SCRIPTS/build_container.sh"
# Deterministic epoch derived from the exact ratified commit (not wall clock, not a
# floating HEAD). The detailed epoch-validation checks are in the item-2 section below.
has "$BC" 'SOURCE_DATE_EPOCH="$(git -C "$ROOT" show -s --format=%ct "$source_commit")"' \
  && ok "SOURCE_DATE_EPOCH derived from the ratified commit's committer date" \
  || bad "SOURCE_DATE_EPOCH not derived from the ratified commit"
has "$BC" '--build-arg "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH"' \
  && ok "SOURCE_DATE_EPOCH passed to the build" || bad "SOURCE_DATE_EPOCH not passed to the build"
has "$BC" 'type=oci,dest=$tar,rewrite-timestamp=true' \
  && ok "OCI exporter uses rewrite-timestamp=true (normalizes layer file mtimes)" \
  || bad "OCI exporter does not use rewrite-timestamp=true"
# The equality gate must remain the strong manifest-identity check (not weakened to a tar
# hash, not normalized away).
has "$BC" '[ "$m1" = "$m2" ] || die "two clean builds diverge in OCI manifest identity' \
  && ok "manifest-identity equality gate unchanged (m1==m2 still fatal)" \
  || bad "manifest-identity equality gate was weakened/removed"
grep -qF 'not a tar hash' "$SCRIPTS/../../b0-pre-validator/src/venue/oci_layout.rs" \
  && ok "identity remains the parsed manifest content address, not a tar hash" \
  || bad "manifest-identity provenance note missing"

for df in sp1 risc0; do
  DF="$CONTAINERS/$df.Dockerfile"
  has "$DF" 'ARG SOURCE_DATE_EPOCH' \
    && ok "$df.Dockerfile declares SOURCE_DATE_EPOCH" || bad "$df.Dockerfile missing ARG SOURCE_DATE_EPOCH"
  # in-layer content normalization: EXPLICIT timestamped logs removed in the apt RUN
  # (narrow paths, not a broad /var/log/* — the dpkg DB, package contents, trust roots,
  # ld.so.cache and toolchain are kept).
  { has "$DF" '/var/log/dpkg.log' && has "$DF" '/var/log/apt' && has "$DF" '/var/log/alternatives.log'; } \
    && ok "$df.Dockerfile drops explicit timestamped logs in-layer (content determinism)" \
    || bad "$df.Dockerfile does not drop the explicit timestamped logs in-layer"
  # Must NOT nuke the package database or a broad /var/log/* (cleanup-scope safety).
  grep -qF '/var/log/*' "$DF" && bad "$df.Dockerfile still uses a broad /var/log/* removal" \
    || ok "$df.Dockerfile avoids broad /var/log/* removal"
  grep -qE 'rm[^\n]*(/var/lib/dpkg/status([^-]|$)|/var/lib/dpkg/info)' "$DF" \
    && bad "$df.Dockerfile removes package database state" \
    || ok "$df.Dockerfile keeps the dpkg package database"
  has "$DF" '/root/.rustup/downloads' \
    && ok "$df.Dockerfile drops rustup download scratch in-layer" \
    || bad "$df.Dockerfile does not drop rustup download scratch"
done

# --- SOURCE_DATE_EPOCH input validation (item 2) ---
# behavioural (via lib.sh): non-empty base-10 integer, positive, no overflow.
# shellcheck source=../lib.sh
. "$SCRIPTS/lib.sh"; set +e
( require_valid_source_date_epoch 1700000000 ) >/dev/null 2>&1 && ok "epoch: valid integer accepted" || bad "epoch: valid integer rejected"
( require_valid_source_date_epoch "" ) >/dev/null 2>&1 && bad "epoch: empty accepted" || ok "epoch: empty rejected"
( require_valid_source_date_epoch abc ) >/dev/null 2>&1 && bad "epoch: non-numeric accepted" || ok "epoch: non-numeric rejected"
( require_valid_source_date_epoch -5 ) >/dev/null 2>&1 && bad "epoch: negative accepted" || ok "epoch: negative rejected"
( require_valid_source_date_epoch 12345678901234567890 ) >/dev/null 2>&1 && bad "epoch: 20-digit overflow accepted" || ok "epoch: overflow rejected"
# source-level: derived from the EXACT ratified commit, proven == RATIFIED, validated pre-Docker.
has "$BC" 'SOURCE_DATE_EPOCH="$(git -C "$ROOT" show -s --format=%ct "$source_commit")"' \
  && ok "epoch derived from the exact ratified commit (not a floating HEAD)" || bad "epoch not derived from the explicit ratified commit"
has "$BC" 'require_valid_source_date_epoch "$SOURCE_DATE_EPOCH"' \
  && ok "epoch validated before Docker" || bad "epoch not validated before Docker"
has "$BC" '[ "$source_commit" = "$RATIFIED_SOURCE_COMMIT" ]' \
  && ok "epoch source proven == RATIFIED_SOURCE_COMMIT" || bad "epoch source not proven == RATIFIED_SOURCE_COMMIT"
n_assign="$(grep -cF 'SOURCE_DATE_EPOCH="$(git -C "$ROOT" show' "$BC")"
[ "$n_assign" = "1" ] && ok "SOURCE_DATE_EPOCH computed exactly once (same value for both clean builds)" || bad "SOURCE_DATE_EPOCH computed $n_assign times (must be 1)"

echo "----"
if [ "$fails" -eq 0 ]; then echo "build_reproducibility: ALL SOURCE-LEVEL CHECKS PASS (empirical two-build equality: venue / tier C)"; exit 0
else echo "build_reproducibility: $fails FAILURE(S)" >&2; exit 1; fi
