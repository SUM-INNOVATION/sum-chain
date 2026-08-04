#!/usr/bin/env bash
# v4 pin/proposal contract gate — golden + adversarial vectors via `venue-verify
# pin-contract-check` (the tested Rust decision core in src/venue/pin_contract.rs).
#
# Proves the versioned contract rule end-to-end at the CLI boundary:
#   * a capability-complete v4 proposal (frozen reconciled Stage-5 identity set) is ACCEPTED;
#   * a v3 proposal PARSES but is refused as INELIGIBLE for capability-complete Stage-5;
#   * an unknown contract_version FAILS CLOSED;
#   * every single-value tamper (circuit member, runtime-tree digest, toolchain digest,
#     mutable-tag OCI ref, arm64 backend) is REFUSED.
# Runnable on either venue with no cargo test harness; any drift fails closed (nonzero).
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CRATE="$(cd "$HERE/../.." && pwd)"
FX="$HERE/fixtures"
V4="$FX/pins-v4.capability-complete.json"
V3="$FX/pins-v3.legacy.json"

fails=0
ok()   { printf 'ok    %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1"; fails=$((fails+1)); }

BIN="$CRATE/target/debug/venue-verify"
if [ ! -x "$BIN" ]; then
  echo "building venue-verify ..."
  ( cd "$CRATE" && cargo build -q --bin venue-verify ) || { echo "cargo build failed"; exit 2; }
fi
command -v python3 >/dev/null 2>&1 || { echo "python3 required"; exit 2; }
check() { "$BIN" pin-contract-check "$1" >/dev/null 2>&1; }        # 0 = capability-complete

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

# 1) capability-complete v4 is accepted.
if check "$V4"; then ok "v4 capability-complete accepted"; else fail "v4 fixture was NOT accepted"; fi

# 2) v3 parses but is refused as ineligible.
if check "$V3"; then fail "v3 was accepted (must be ineligible)"; else ok "v3 refused as INELIGIBLE"; fi

# 3) unknown version fails closed.
echo '{"contract_version":"v7"}' > "$WORK/unknown.json"
if check "$WORK/unknown.json"; then fail "unknown version accepted"; else ok "unknown version fails closed"; fi

# 4) missing version fails closed.
echo '{"base_image":"x"}' > "$WORK/nover.json"
if check "$WORK/nover.json"; then fail "missing version accepted"; else ok "missing version fails closed"; fi

# helper: mutate the v4 fixture with a python expression, then expect refusal.
mutate_reject() { # <label> <python-mutation on dict `d`>
  local label="$1" mut="$2" out="$WORK/mut.json"
  python3 -c "import json,sys
d=json.load(open('$V4'))
$mut
json.dump(d,open('$out','w'))"
  if check "$out"; then fail "$label was accepted (must be refused)"; else ok "$label refused"; fi
}

mutate_reject "altered circuit member sha256" \
  "[m.__setitem__('sha256','0'*64) for m in d['groth16_circuit_artifact']['members'] if m['path']=='groth16_pk.bin']"
mutate_reject "altered circuit member size" \
  "[m.__setitem__('size',1) for m in d['groth16_circuit_artifact']['members'] if m['path']=='groth16_vk.bin']"
mutate_reject "corrupted runtime-tree digest" \
  "d['groth16_circuit_artifact'].__setitem__('runtime_tree_blake3','0'*64)"
mutate_reject "extra AppleDouble sidecar" \
  "d['groth16_circuit_artifact']['members'].append({'path':'._evil','kind':'appledouble','size':163,'sha256':'a8d7edcaf5cde6ccdb9d056770ecd3edadcdd9010dad9d9b61e026f4732cd0e0'})"
mutate_reject "AppleDouble leaked into runtime_members" \
  "d['groth16_circuit_artifact']['runtime_members'].append('._groth16_pk.bin')"
mutate_reject "corrupted toolchain tree digest" \
  "d['guest_toolchains'][0].__setitem__('provisioned_tree_blake3','1'*64)"
mutate_reject "mutable-tag OCI reference" \
  "d['oci_backends'][0].__setitem__('index_digest','ghcr.io/succinctlabs/sp1-gnark:v6.1.0')"
mutate_reject "arm64 terminal-Groth16 backend" \
  "d['oci_backends'][0].__setitem__('platform','linux/arm64')"
# OCI identity conflation matrix (index / manifest / config / image-id / attestation).
mutate_reject "loaded_image_id conflated with index" \
  "d['oci_backends'][0].__setitem__('loaded_image_id', d['oci_backends'][0]['index_digest'])"
mutate_reject "loaded_image_id conflated with manifest (RISC0 bug)" \
  "d['oci_backends'][1].__setitem__('loaded_image_id', d['oci_backends'][1]['amd64_manifest_digest'])"
mutate_reject "config conflated with index (SP1 bug)" \
  "b=d['oci_backends'][0]; b['config_digest']=b['index_digest']; b['loaded_image_id']=b['index_digest']"
mutate_reject "config conflated with manifest" \
  "b=d['oci_backends'][0]; b['config_digest']=b['amd64_manifest_digest']; b['loaded_image_id']=b['amd64_manifest_digest']"
mutate_reject "swapped index and manifest" \
  "b=d['oci_backends'][0]; b['index_digest'],b['amd64_manifest_digest']=b['amd64_manifest_digest'],b['index_digest']"
mutate_reject "sp1 missing attestation" \
  "d['oci_backends'][0].pop('attestation_digest')"
mutate_reject "risc0 spurious attestation" \
  "d['oci_backends'][1].__setitem__('attestation_digest','sha256:6ade751e47f161a6d351675c72619ca9f9dff685c41962985e40e2b2289696b9')"
mutate_reject "wrong config digest (distinct but not the resolved config)" \
  "b=d['oci_backends'][0]; w='sha256:'+'1'*64; b['config_digest']=w; b['loaded_image_id']=w"
mutate_reject "risc0 aarch64 toolchain" \
  "d['guest_toolchains'].append({'framework':'risc0','arch':'aarch64','toolchain_version':'x','archive_sha256':'0'*64,'provisioned_tree_blake3':'0'*64,'ratification':'unratified'})"
mutate_reject "ratified flag (must be unratified)" \
  "d['guest_toolchains'][0].__setitem__('ratification','ratified')"
mutate_reject "unknown field in a new block" \
  "d['oci_backends'][0].__setitem__('surprise','x')"
mutate_reject "dropped required block (oci_backends)" \
  "d.pop('oci_backends')"

echo
if [ "$fails" -eq 0 ]; then echo "v4 pin-contract vectors: ALL PASS"; exit 0
else echo "v4 pin-contract vectors: $fails FAILED"; exit 1; fi
