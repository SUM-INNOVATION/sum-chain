#!/usr/bin/env bash
# Provision + SEAL the ONE authenticated, content-addressed OFFLINE dependency seed for the canonical SP1
# guest build. This is the SINGLE disclosed network step: it runs the RATIFIED, identity-attested
# `cargo +1.90.0 vendor --locked` (NOT ambient cargo) exactly once against the committed candidates/sp1
# lock, then seals the EXACT vendored bytes + config + an authority record. Every canonical-guest A/B
# build afterwards CONSUMES these copied bytes offline (network-denied) and NEVER re-vendors. The prior
# 8584a56d seed (provisioned by ambient, unratified cargo 1.97.1) is SUPERSEDED.
#
#   provision_sp1_guest_seed.sh <measured-source-root> <out-seed-pkg-dir> [cargo-toolchain=1.90.0]
#
# <measured-source-root> is the <checkout>/tools/b0-pre-candidates root that contains candidates/sp1
# (the ratified measured source). The sealed package layout:
#   <pkg>/vendor/                                (exact cargo +1.90 vendored crates — NOT normalized)
#   <pkg>/config.toml                            (canonical directory + [net] offline)
#   <pkg>/sp1-guest-dep-seed-authority.v1.json   (the authority record; own SHA-256 content address)
#   <pkg>/.content-address                       (= the record address)
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$HERE/lib.sh"
die() { echo "REFUSED: $*" >&2; exit 1; }

MSRC="${1:-}"; OUT="${2:-}"; TC="${3:-1.90.0}"
[ -n "$MSRC" ] && [ -n "$OUT" ] || die "usage: provision_sp1_guest_seed.sh <measured-source-root> <out-seed-pkg-dir> [cargo-toolchain=1.90.0]"
[ "$TC" = 1.90.0 ] || die "seed provisioning toolchain must be the ratified x86 host cargo 1.90.0 (got '$TC'); ambient/other cargo is refused"
CAND_SP1="$MSRC/candidates/sp1"
[ -d "$CAND_SP1" ] || die "measured source root lacks candidates/sp1: $CAND_SP1"
LOCK="$CAND_SP1/Cargo.lock"
[ -s "$LOCK" ] || die "candidates/sp1/Cargo.lock absent/empty: $LOCK"
[ -e "$OUT" ] && die "out seed-pkg dir already exists; refuse to overwrite: $OUT"
require_cmd() { command -v "$1" >/dev/null 2>&1 || die "required command '$1' not found"; }
require_cmd b3sum; require_cmd sha256sum; require_cmd python3; require_cmd git

# The ratified 1.90 cargo, attested by identity (binary blake3 + version + toolchain triple).
CARGO_BIN="$(rustup which --toolchain "$TC" cargo 2>/dev/null)" || die "rustup toolchain $TC not installed"
[ -x "$CARGO_BIN" ] || die "cargo $TC binary not executable: $CARGO_BIN"
CARGO_VER="$("$CARGO_BIN" --version 2>/dev/null)" || die "cargo $TC --version failed"
CARGO_B3="$(b3sum "$CARGO_BIN" | awk '{print $1}')"
TC_TRIPLE="$TC-x86_64-unknown-linux-gnu"

# Measured source commit (from the measured checkout HEAD).
SRC_COMMIT="$(git -C "$MSRC" rev-parse HEAD 2>/dev/null || true)"
printf '%s' "$SRC_COMMIT" | grep -Eq '^[0-9a-f]{40}$' || die "cannot read a 40-hex measured source commit from $MSRC"

work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
seedtmp="$work/seed"; mkdir -p "$seedtmp/vendor"
seed="$seedtmp/vendor"; seed_config="$seedtmp/config.toml"

# ---- THE ONE DISCLOSED NETWORK ACTION: cargo +1.90.0 vendor --locked ----------------------------------
echo "### provisioning SP1 guest dependency seed via ATTESTED cargo $TC vendor --locked (ONE disclosed crates.io fetch)" >&2
CMD="cargo +$TC vendor --locked --versioned-dirs vendor"
( cd "$CAND_SP1" && CARGO_HOME="$work/prov" "$CARGO_BIN" vendor --locked --versioned-dirs "$seed" ) > "$seed_config" 2>"$work/vendor.err" \
  || { sed -n '1,12p' "$work/vendor.err" >&2; die "cargo $TC vendor --locked failed"; }
rm -rf "$work/prov"
# canonicalize the vendor config directory (cargo records the absolute mktemp path) + force offline.
sed -i 's#^directory = .*#directory = "/b0/canonical/sp1-guest-vendor"#' "$seed_config"
b0_config_add_offline "$seed_config"
[ -f "$seed/.cargo-checksum.json" ] 2>/dev/null || true   # (vendor root has no top-level checksum; per-crate)

# ---- authenticated addresses of the sealed bytes -----------------------------------------------------
SEED_ADDR="$(b0_seed_inventory_address "$seedtmp")" || die "seed inventory address failed"
[ "$SEED_ADDR" != "$B0_SP1_DEP_SEED_SUPERSEDED_ADDR" ] \
  || die "provisioned seed is the SUPERSEDED $B0_SP1_DEP_SEED_SUPERSEDED_ADDR (ambient/unratified cargo 1.97.1); the ratified cargo $TC seed must not equal it"
VENDOR_CONFIG_SHA="$(sha256sum "$seed_config" | awk '{print $1}')"
LOCK_SHA="$(sha256sum "$LOCK" | awk '{print $1}')"
LOCK_B3="$(b3sum "$LOCK" | awk '{print $1}')"

# ---- package coordinates + crates.io checksums, from the COMMITTED lock (authoritative graph) --------
PKGS_JSON="$(python3 - "$LOCK" <<'PY'
import sys, re, json
txt = open(sys.argv[1], encoding="utf-8").read()
pkgs = []
for blk in txt.split("[[package]]")[1:]:
    def g(k):
        m = re.search(r'^%s = "([^"]*)"' % k, blk, re.M)
        return m.group(1) if m else ""
    name, ver = g("name"), g("version")
    if name and ver:
        pkgs.append({"name": name, "version": ver, "source": g("source"), "crates_io_checksum": g("checksum")})
print(json.dumps(pkgs))
PY
)"
PKG_COUNT="$(python3 -c 'import json,sys;print(len(json.loads(sys.stdin.read())))' <<<"$PKGS_JSON")"
[ "$PKG_COUNT" -gt 0 ] 2>/dev/null || die "no [[package]] entries parsed from the lock"

# ---- build the authority record + its content address ------------------------------------------------
mkdir -p "$OUT/vendor"
cp -a "$seed/." "$OUT/vendor/"
cp -a "$seed_config" "$OUT/config.toml"
REC="$OUT/sp1-guest-dep-seed-authority.v1.json"
# recompute the sealed-copy seed address (bytes intact after copy) BEFORE writing the record.
COPY_ADDR="$(b0_seed_inventory_address "$OUT")" || die "sealed-copy seed inventory address failed"
[ "$COPY_ADDR" = "$SEED_ADDR" ] || die "sealed copy seed address $COPY_ADDR != provisioned $SEED_ADDR (copy corrupted)"
python3 - "$REC" "$B0_SP1_DEP_SEED_AUTHORITY_DOMAIN" "$SRC_COMMIT" "$LOCK_SHA" "$LOCK_B3" "$SEED_ADDR" \
  "$VENDOR_CONFIG_SHA" "$CARGO_VER" "$CARGO_B3" "$TC_TRIPLE" "$CMD" "$PKG_COUNT" "$PKGS_JSON" <<'PY'
import json, sys, hashlib
(out, domain, src, lsha, lb3, seed_addr, vcfg, cver, cb3, triple, cmd, pcount, pkgs_json) = sys.argv[1:14]
pkgs = json.loads(pkgs_json)
rec = {
    "schema": domain,
    "measured_source_commit": src,
    "guest_lock_sha256": lsha, "guest_lock_blake3": lb3,
    "seed_inventory_address": seed_addr,
    "vendor_config_sha256": vcfg,
    "provisioning": {
        "cargo_version": cver, "cargo_bin_blake3": cb3, "toolchain": triple, "command": cmd,
        "network_action": "ONE disclosed crates.io fetch during this provisioning step; all canonical-guest builds that consume this seed run --locked --offline with CARGO_NET_OFFLINE=true and container network denial.",
    },
    "package_count": int(pcount),
    "packages": pkgs,
    "superseded": {"address": "8584a56d37b508de9648a1c1c4207648884a6c24e910e07cde7943473f219d6b",
                   "reason": "provisioned by ambient, unratified cargo 1.97.1 (excludes cargo-1.90 VCS/dev metadata); superseded by the ratified cargo 1.90.0 seed"},
}
# venue-independent content address (identical logic to lib.sh b0_sp1_dep_seed_authority_address)
p = rec["provisioning"]
fields = [domain, rec["measured_source_commit"], rec["guest_lock_sha256"], rec["guest_lock_blake3"],
          rec["seed_inventory_address"], rec["vendor_config_sha256"],
          p["cargo_version"], p["cargo_bin_blake3"], p["toolchain"], p["command"], str(rec["package_count"])]
for pk in sorted(pkgs, key=lambda x: (x["name"], x["version"])):
    fields += [pk["name"], pk["version"], pk.get("source", ""), pk.get("crates_io_checksum", "")]
rec["address"] = hashlib.sha256("\0".join(fields).encode()).hexdigest()
with open(out, "w", encoding="utf-8") as f:
    json.dump(rec, f, indent=1, sort_keys=True); f.write("\n")
print(rec["address"])
PY
ADDR="$(b0_sp1_dep_seed_authority_address "$REC")" || die "authority address recompute failed"
REC_ADDR="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["address"])' "$REC")"
[ "$ADDR" = "$REC_ADDR" ] || die "authority record address $REC_ADDR != recomputed $ADDR (record tampered)"
printf '%s\n' "$ADDR" > "$OUT/.content-address"

echo "### SEALED SP1 guest dep-seed authority" >&2
echo "SP1_DEP_SEED_AUTHORITY_ADDRESS=$ADDR"
echo "SEED_INVENTORY_ADDRESS=$SEED_ADDR"
echo "PACKAGE_COUNT=$PKG_COUNT"
echo "PROVISIONING_CARGO=$CARGO_VER (blake3 $CARGO_B3)"
echo "SEED_PKG=$OUT"
