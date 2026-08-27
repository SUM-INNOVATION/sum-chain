#!/usr/bin/env bash
# Produce (or verify) the ONE canonical SP1 zkVM guest ELF artifact.
#
# The B0-FINAL grid compares proving implementations/hosts against a SINGLE program. SP1's
# per-arch succinct cross-compiler does NOT emit a byte-identical guest ELF across build-host
# architectures (x86 vs aarch64 diverge even with identical source+lock+rustc+LLVM), so the
# guest is built ONCE, on the ratified x86 authority, sealed here, and the EXACT bytes are
# distributed to every proving architecture. No official SP1 path may `cargo prove build`; both
# arches consume THESE bytes and independently verify this package.
#
# Usage:
#   produce_canonical_sp1_guest.sh produce <measured-source-root> <tooling-root> <out-package-dir>
#   produce_canonical_sp1_guest.sh verify  <package-dir>
#
# produce (x86_64 authority only):
#   * require_two_roots (measured==RATIFIED_SOURCE_COMMIT, tooling clean); guest source+lock
#     from the MEASURED root only.
#   * VERIFIER_REF (pinned SP1 builder image) must reconcile to the ratified Sp1/x86_64 identity.
#   * materialize an OFFLINE guest dependency seed (cargo vendor --locked of candidates/sp1).
#   * build the guest ELF TWICE in independent clean roots, inside the image, with
#     --network none + CARGO_NET_OFFLINE + --offline + --locked (never latest crates.io).
#   * require the two ELFs byte-identical (cmp + sha256 + blake3); build B starts after build A.
#   * derive program_id (SP1 vkey) + guest_image_hash (blake3 ELF) from the retained ELF.
#   * seal CanonicalSp1GuestArtifactV1 (guest.elf + manifest with domain-separated address).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
# shellcheck source=lib.sh
. "$HERE/lib.sh"
# shellcheck source=two_root_authority.sh
. "$HERE/two_root_authority.sh"

CANON_SCHEMA='b0-final-canonical-sp1-guest-artifact/v1'
CANON_PKG_DOMAIN='b0-final-canonical-sp1-guest-package/v1'
CANON_ENV_DOMAIN='b0-final-canonical-sp1-guest-buildenv/v1'
ARTIFACT_JSON_NAME='canonical-sp1-guest-artifact.v1.json'
ELF_NAME='guest.elf'
INCAND='/work/tools/b0-pre-candidates/candidates/sp1'   # incontainer_candidate_dir sp1

b3() { b3sum "$1" | awk '{print $1}'; }
die() { echo "REFUSED: $*" >&2; exit 1; }
note() { echo "[canonical-sp1] $*" >&2; }

MODE="${1:-}"; shift || true

# ---- package content address: DOMAIN\0 + sorted "<member_blake3>  <relpath>" -> b3sum ----
canon_package_address() { # <package-dir>
  local dir="$1" man
  man="$(cd "$dir" && find . -type f ! -name '.content-address' | LC_ALL=C sort \
    | while IFS= read -r f; do printf '%s  %s\n' "$(b3 "$f")" "${f#./}"; done)"
  { printf '%s\0' "$CANON_PKG_DOMAIN"; printf '%s' "$man"; } | b3sum | awk '{print $1}'
}

# The exact in-container guest build command line (bound verbatim into build_argv). `cargo prove
# build` takes no --offline flag; offline is enforced by docker --network none + CARGO_NET_OFFLINE
# + the vendored source-replacement config + --locked (recorded via build_env_address).
CANON_BUILD_ARGV="cargo prove build --locked --output-directory /out/guest --elf-name $ELF_NAME"

produce() {
  local MSRC="${1:-}" TSRC="${2:-}" OUT="${3:-}"
  [ -n "$MSRC" ] && [ -n "$TSRC" ] && [ -n "$OUT" ] || die "usage: produce <measured-root> <tooling-root> <out-dir>"
  [ -n "${VERIFIER_REF:-}" ] || die "VERIFIER_REF (pinned SP1 x86_64 builder image) required"
  [ -n "${PROVER_REAL_DOCKER:-}" ] || die "PROVER_REAL_DOCKER required"
  [ -n "${MEASURE_RUNNER:-}" ] || die "MEASURE_RUNNER (b0-pre-measure-sp1, to derive program_id/guest_image_hash) required"
  [ -x "$MEASURE_RUNNER" ] || die "MEASURE_RUNNER not executable: $MEASURE_RUNNER"
  require_cmd b3sum; require_cmd sha256sum; require_cmd python3; require_cmd cargo
  local rd; rd="$(readlink -f "$PROVER_REAL_DOCKER")"

  # native x86_64 authority only.
  require_native_arch x86_64

  # two-root authority (measured HEAD == RATIFIED_SOURCE_COMMIT, both clean, non-nested).
  require_two_roots --measured-source-root "$MSRC" --tooling-root "$TSRC"
  export B0_MEASURED_ROOT B0_MEASURED_COMMIT B0_TOOLING_ROOT B0_TOOLING_COMMIT B0_TOOLING_PATHSET_BLAKE3

  local guest_dir="$B0_MEASURED_ROOT/candidates/sp1/guest"
  local lock="$B0_MEASURED_ROOT/candidates/sp1/Cargo.lock"
  local ws_manifest="$B0_MEASURED_ROOT/candidates/sp1/Cargo.toml"
  [ -d "$guest_dir" ] && [ -s "$lock" ] && [ -s "$ws_manifest" ] || die "SP1 guest tree/lock/workspace-manifest absent in measured root"
  local guest_lock_sha256 guest_lock_blake3
  guest_lock_sha256="$(sha256sum "$lock" | awk '{print $1}')"
  guest_lock_blake3="$(b3 "$lock")"

  # ratified toolchain identity: the builder image .Id must reconcile to Sp1/x86_64.
  local img; img="$("$rd" image inspect --format '{{.Id}}' "$VERIFIER_REF" 2>/dev/null || true)"
  case "$img" in sha256:*) ;; *) die "VERIFIER_REF did not reconcile to an immutable image id" ;; esac
  local builder_config_digest; builder_config_digest="$("$rd" image inspect --format '{{.Id}}' "$VERIFIER_REF" | sed 's/^sha256://')"
  local builder_platform; builder_platform="$("$rd" image inspect --format '{{.Os}}/{{.Architecture}}' "$VERIFIER_REF" 2>/dev/null || echo unknown)"
  [ "$builder_platform" = "linux/amd64" ] || die "builder image platform $builder_platform != linux/amd64 (canonical authority is x86_64)"
  local sp1_tc; sp1_tc="$(b0_toolchain_identity sp1 "$img")"
  : "${TOOLCHAIN_AUTHORITY_RECORD:=$ROOT/../../docs/b0-pre/venue/toolchain-authority.v1.json}"
  local ratified_tc; ratified_tc="$(b0_ratified_toolchain_identity Sp1 x86_64 "$TOOLCHAIN_AUTHORITY_RECORD")" \
    || die "ratified toolchain authority record unavailable/invalid"
  [ "$sp1_tc" = "$ratified_tc" ] || die "SP1 builder toolchain identity $sp1_tc != ratified $ratified_tc"

  local work; work="$(mktemp -d)"; trap 'rm -rf "${work:-}"' EXIT

  # ---- CONSUME the ONE authenticated, content-addressed OFFLINE dependency seed (NO live re-vendor) ----
  # The seed was provisioned ONCE by provision_sp1_guest_seed.sh (the single disclosed cargo +1.90.0 vendor
  # network step) and sealed. Here we ONLY verify + materialize COPIED bytes; we NEVER re-vendor and NEVER
  # touch the network. A missing / mutated / substituted / superseded (8584a56d, ambient cargo 1.97.1) /
  # wrong-lock / non-1.90 seed is refused. The A/B builds below run --locked --offline + --network none.
  # ONE shared authentication (lib.sh b0_authenticate_sp1_guest_seed_pkg) the tests drive too, so producer
  # and tests cannot drift: it re-authenticates the authority record from scratch, enforces policy (NOT the
  # superseded 8584a56d ambient-1.97.1 seed; provisioned by the ratified cargo 1.90.0; guest lock == THIS
  # committed lock), materializes the copied {vendor,config} bytes into $work/seed, and re-verifies the
  # materialized inventory == sealed. Prints `<authority_addr> <seed_inventory_addr> <vendor_config_sha256>`.
  [ -n "${B0_SP1_GUEST_DEP_SEED_PKG:-}" ] || die "B0_SP1_GUEST_DEP_SEED_PKG (the sealed, authenticated SP1 guest dep-seed package) is required"
  local dep_seed_authority_address dep_seed_address vendor_config_sha256 _seedline
  _seedline="$(b0_authenticate_sp1_guest_seed_pkg "$B0_SP1_GUEST_DEP_SEED_PKG" "$guest_lock_sha256" "$work/seed")" \
    || die "SP1 guest dep-seed authentication failed (see REFUSED above)"
  read -r dep_seed_authority_address dep_seed_address vendor_config_sha256 <<<"$_seedline"
  local seed="$work/seed/vendor" seed_config="$work/seed/config.toml"
  note "consumed sealed SP1 guest dep-seed authority $dep_seed_authority_address (seed $dep_seed_address; NO re-vendor; offline)"

  # ---- build the guest ELF TWICE in independent clean roots, OFFLINE (--network none) ----
  # Vendored crates mounted read-only at a FIXED path; a fixed source-replacement config
  # redirects crates.io to it; --network none + CARGO_NET_OFFLINE + --offline + --locked make
  # the build resolve ONLY the frozen committed lock. Independent CARGO_TARGET_DIR per build.
  local a_start a_end b_start b_end a_elf b_elf
  build_one() { # <label> <out-host-dir> <log>
    local label="$1" outh="$2" logf="$3"; mkdir -p "$outh"
    "$rd" run --rm --pull never --network none \
      -v "$outh:/out" \
      -v "$seed:/b0seed/vendor:ro" \
      -v "$lock:$INCAND/Cargo.lock:ro" \
      -e CARGO_TARGET_DIR=/tmp/b0pre-guest-target-"$label" \
      "$VERIFIER_REF" bash -c "
        set -e; export PATH=/root/.cargo/bin:\$PATH CARGO_NET_OFFLINE=true
        mkdir -p $INCAND/.cargo
        printf '[source.crates-io]\nreplace-with = \"vendored-sources\"\n[source.vendored-sources]\ndirectory = \"/b0seed/vendor\"\n' > $INCAND/.cargo/config.toml
        cd $INCAND/guest && cargo prove build --locked --output-directory /out/guest --elf-name $ELF_NAME
      " >"$logf" 2>&1 || { sed -n '1,20p' "$logf" >&2; die "SP1 guest build $label failed (offline)"; }
    [ -s "$outh/guest/$ELF_NAME" ] || die "SP1 guest ELF $label absent"
  }
  a_start="$(date -u +%s)"; build_one A "$work/out-a" "$work/build-a.log"; a_end="$(date -u +%s)"
  b_start="$(date -u +%s)"; build_one B "$work/out-b" "$work/build-b.log"; b_end="$(date -u +%s)"
  [ "$b_start" -ge "$a_end" ] || die "build B did not start after build A ended (no wall-clock separation)"
  a_elf="$work/out-a/guest/$ELF_NAME"; b_elf="$work/out-b/guest/$ELF_NAME"
  cmp -s "$a_elf" "$b_elf" || die "canonical guest ELF is NOT reproducible: build A != build B"
  local a_sha b_sha a_bl b_bl
  a_sha="$(sha256sum "$a_elf" | awk '{print $1}')"; b_sha="$(sha256sum "$b_elf" | awk '{print $1}')"
  a_bl="$(b3 "$a_elf")"; b_bl="$(b3 "$b_elf")"
  [ "$a_sha" = "$b_sha" ] && [ "$a_bl" = "$b_bl" ] || die "A/B hash mismatch despite cmp (impossible; refusing)"

  local elf_size elf_sha256 elf_blake3
  elf_size="$(stat -c%s "$a_elf" 2>/dev/null || stat -f%z "$a_elf")"
  elf_sha256="$a_sha"; elf_blake3="$a_bl"

  # command-log address (bare blake3 of the concatenated unbuffered build logs, A then B).
  # DETERMINISTIC command-log address: the fixed in-container build command + offline env (never the
  # raw timestamped logs, which are provenance, not identity). Two produces yield the same address.
  local command_log_address
  command_log_address="$( { printf '%s\0' "$CANON_ENV_DOMAIN"; printf 'cmd=%s\nnetwork=none\noffline=true\n' "$CANON_BUILD_ARGV"; } | b3sum | awk '{print $1}')"
  # build-env address: domain-separated blake3 over the fixed offline env (sorted).
  local build_env_address
  build_env_address="$( { printf '%s\0' "$CANON_ENV_DOMAIN"; printf 'CARGO_NET_OFFLINE=true\nCARGO_HOME=/b0seed/cargo\nnetwork=none\n'; } | b3sum | awk '{print $1}')"

  # ---- derive program_id (SP1 vkey) + guest_image_hash from the retained ELF (no rebuild) ----
  note "deriving program_id (SP1 vkey) + guest_image_hash from the sealed ELF"
  local derive_json; derive_json="$("$MEASURE_RUNNER" --derive-guest-identity --guest-elf "$a_elf" 2>"$work/derive.err")" \
    || { sed -n '1,8p' "$work/derive.err" >&2; die "program_id/guest_image_hash derivation failed"; }
  local program_id guest_image_hash
  program_id="$(printf '%s' "$derive_json" | python3 -c 'import json,sys;print(json.load(sys.stdin)["program_id"])')"
  guest_image_hash="$(printf '%s' "$derive_json" | python3 -c 'import json,sys;print(json.load(sys.stdin)["guest_image_hash"])')"
  [ "$guest_image_hash" = "$elf_blake3" ] || die "guest_image_hash ($guest_image_hash) != blake3(ELF) ($elf_blake3); refusing"

  # ---- seal the package: guest.elf + manifest with the domain-separated artifact address ----
  rm -rf "$OUT"; mkdir -p "$OUT"
  cp "$a_elf" "$OUT/$ELF_NAME"
  python3 - "$OUT/$ARTIFACT_JSON_NAME" <<PY
import json,sys,hashlib
fields=dict(
  schema="$CANON_SCHEMA", candidate="sp1", canonical_build_arch="x86_64",
  measured_source_commit="$B0_MEASURED_COMMIT",
  tooling_commit="$B0_TOOLING_COMMIT", tooling_pathset_blake3="$B0_TOOLING_PATHSET_BLAKE3",
  staged_context_blake3="",  # reserved; the guest workspace is the measured tree, addressed by the lock+source below
  guest_lock_sha256="$guest_lock_sha256", guest_lock_blake3="$guest_lock_blake3",
  dependency_seed_address="$dep_seed_address", vendor_config_sha256="$vendor_config_sha256",
  dependency_seed_authority_address="$dep_seed_authority_address",
  builder_image_id="${img#sha256:}", builder_config_digest="$builder_config_digest",
  builder_platform="$builder_platform", sp1_toolchain_identity="$sp1_tc",
  build_argv="$CANON_BUILD_ARGV",
  build_env_address="$build_env_address", command_log_address="$command_log_address",
  build_a=dict(elf_sha256="$a_sha", elf_blake3="$a_bl"),
  build_b=dict(elf_sha256="$b_sha", elf_blake3="$b_bl"),
  double_build_proof=dict(byte_identical=True, cmp_ok=True, sha256_equal=True, blake3_equal=True,
                          wallclock_separated=True),
  elf_size=$elf_size, elf_sha256="$elf_sha256", elf_blake3="$elf_blake3",
  program_id="$program_id", guest_image_hash="$guest_image_hash",
)
def addr(f):
    pre="\0".join([
      f["schema"], f["candidate"], f["canonical_build_arch"], f["measured_source_commit"],
      f["tooling_commit"], f["tooling_pathset_blake3"], f["staged_context_blake3"],
      f["guest_lock_sha256"], f["guest_lock_blake3"], f["dependency_seed_address"], f["vendor_config_sha256"],
      f["dependency_seed_authority_address"],
      f["builder_image_id"], f["builder_config_digest"], f["builder_platform"], f["sp1_toolchain_identity"],
      f["build_argv"], f["build_env_address"], f["command_log_address"],
      f["build_a"]["elf_sha256"], f["build_b"]["elf_sha256"],
      str(f["elf_size"]), f["elf_sha256"], f["elf_blake3"], f["program_id"], f["guest_image_hash"],
    ])
    return hashlib.sha256(pre.encode()).hexdigest()
fields["address"]=addr(fields)
json.dump(fields, open(sys.argv[1],"w"), indent=1, sort_keys=True); open(sys.argv[1],"a").write("\n")
PY
  local pkg_addr; pkg_addr="$(canon_package_address "$OUT")"
  printf '%s\n' "$pkg_addr" > "$OUT/.content-address"
  local art_addr; art_addr="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["address"])' "$OUT/$ARTIFACT_JSON_NAME")"
  note "sealed CanonicalSp1GuestArtifactV1 -> $OUT"
  note "  artifact_address=$art_addr"
  note "  package_address =$pkg_addr"
  note "  elf: size=$elf_size sha256=$elf_sha256"
  note "  program_id=$program_id guest_image_hash=$guest_image_hash"
  echo "$art_addr"
}

verify() { # <package-dir>  (independent, no ratification record required beyond the toolchain authority for the identity check)
  local PKG="${1:-}"; [ -d "$PKG" ] || die "usage: verify <package-dir>"
  require_cmd b3sum; require_cmd sha256sum; require_cmd python3
  local man="$PKG/$ARTIFACT_JSON_NAME" elf="$PKG/$ELF_NAME"
  [ -s "$man" ] && [ -s "$elf" ] || die "package missing manifest or ELF"
  # recompute everything derivable from the ELF bytes + the manifest.
  local re_size re_sha re_bl
  re_size="$(stat -c%s "$elf" 2>/dev/null || stat -f%z "$elf")"
  re_sha="$(sha256sum "$elf" | awk '{print $1}')"; re_bl="$(b3 "$elf")"
  python3 - "$man" "$re_size" "$re_sha" "$re_bl" <<'PY'
import json,sys,hashlib
man,re_size,re_sha,re_bl=sys.argv[1:5]
f=json.load(open(man))
def bad(m): print("REFUSED: "+m,file=sys.stderr); sys.exit(1)
if f.get("schema")!="b0-final-canonical-sp1-guest-artifact/v1": bad("wrong schema")
if f.get("candidate")!="sp1": bad("candidate!=sp1")
if str(f.get("elf_size"))!=re_size: bad("elf_size %s != actual %s"%(f.get("elf_size"),re_size))
if f.get("elf_sha256")!=re_sha: bad("elf_sha256 mismatch (ELF bytes changed)")
if f.get("elf_blake3")!=re_bl: bad("elf_blake3 mismatch (ELF bytes changed)")
if f.get("guest_image_hash")!=re_bl: bad("guest_image_hash != blake3(ELF)")
if not (f.get("build_a",{}).get("elf_sha256")==re_sha==f.get("build_b",{}).get("elf_sha256")): bad("A/B double-build proof does not match the sealed ELF")
dbp=f.get("double_build_proof",{})
if not all(dbp.get(k) for k in ("byte_identical","cmp_ok","sha256_equal","blake3_equal","wallclock_separated")): bad("incomplete/non-reproducible double-build proof")
if not f.get("dependency_seed_authority_address"): bad("missing dependency_seed_authority_address (canonical guest not built from the sealed authenticated seed)")
pre="\0".join([f[k] for k in ["schema","candidate","canonical_build_arch","measured_source_commit","tooling_commit","tooling_pathset_blake3","staged_context_blake3","guest_lock_sha256","guest_lock_blake3","dependency_seed_address","vendor_config_sha256","dependency_seed_authority_address","builder_image_id","builder_config_digest","builder_platform","sp1_toolchain_identity","build_argv","build_env_address","command_log_address"]]
    +[f["build_a"]["elf_sha256"],f["build_b"]["elf_sha256"],str(f["elf_size"]),f["elf_sha256"],f["elf_blake3"],f["program_id"],f["guest_image_hash"]])
if hashlib.sha256(pre.encode()).hexdigest()!=f.get("address"): bad("artifact address recompute mismatch (manifest tampered)")
print("artifact_address="+f["address"])
print("program_id="+f["program_id"]); print("guest_image_hash="+f["guest_image_hash"])
PY
  local pkg_addr recomputed
  recomputed="$(canon_package_address "$PKG")"
  local stored; stored="$(cat "$PKG/.content-address" 2>/dev/null || true)"
  [ -n "$stored" ] && [ "$stored" != "$recomputed" ] && die "package content address mismatch (member set tampered): stored=$stored recomputed=$recomputed"
  note "verified CanonicalSp1GuestArtifactV1 package $PKG (package_address=$recomputed)"
}

case "$MODE" in
  produce) produce "$@" ;;
  verify)  verify "$@" ;;
  *) die "mode must be produce|verify" ;;
esac
