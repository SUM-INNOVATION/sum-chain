#!/usr/bin/env bash
# Produce the per-candidate proof-tool evidence for the sealed per-arch bundle.
#
# Blocker 6 (the BINDING is the authoritative entry, not the declaration): the
# authoritative path, for each declared proof tool, DOWNLOADS the exact artifact,
# VERIFIES its declared checksum over the bytes, INSTALLS via the declared
# entrypoint, VERIFIES the installed binary, and BINDS the verified-artifact hash +
# installed-binary hash + container/source identity into a `<Candidate>.tool-binding.json`
# record (a `ToolBindingRecord` array). That binding record — NOT the owner's raw
# declaration — is what the sealed evidence bundle requires and re-checks; the
# import-verifier rejects a missing or mismatched binding. The former behaviour
# (bind, then copy the ORIGINAL owner metadata into `<Candidate>.tool.json`,
# discarding the verified hashes) is gone: the Stage-6 declaration `<Candidate>.tool.json`
# is now DERIVED from the verified binding, so it is a projection of verified
# evidence, never an unverified copy.
#
# It NEVER invents installer URLs/checksums; the owner supplies real metadata via
# SP1_TOOL_IDENTITY / RISC0_TOOL_IDENTITY. Off-venue that metadata is absent
# ([MISS]) and there is no network/toolchain, so it fails closed.
#
# OFF-VENUE dry run (SUMCHAIN_B0PRE_DRYRUN=1) emits real-SHAPED files whose installer
# metadata is UNMISTAKABLY SYNTHETIC (carries the TEST_ONLY_SYNTHETIC sentinel) and
# whose binding records are test_only=true — never mistakable for real metadata.
#
# Usage: tool_identities.sh <out_dir>
# Authoritative env: SP1_TOOL_IDENTITY, RISC0_TOOL_IDENTITY (owner metadata files),
#                    SP1_BUILDER_DIGEST, RISC0_BUILDER_DIGEST (sha256:...), SOURCE_COMMIT.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
# shellcheck source=lib.sh
. "$HERE/lib.sh"
require_cmd python3

out="${1:-}"
[ -n "$out" ] || die "output directory argument required"
mkdir -p "$out"

# Frozen pins (mirror run_authoritative.sh / VENUE.md audit policy; not invented).
RUST=1.88.0; SP1_VER=6.3.1; R0_ZKVM=3.0.5; R0_G16=3.0.4
SENTINEL=TEST_ONLY_SYNTHETIC

emit_dry() {
  # candidate rust_version   name:ver[,name:ver...]
  local cand="$1" rustv="$2" tools="$3"
  # A stable synthetic builder digest + source commit for the dry sealed-bundle demo.
  local builder src
  builder="$(syn_oci "builder-$cand")"
  src="$(syn_hex "commit-$cand" | cut -c1-40)"
  python3 - "$out/$cand.tool.json" "$out/$cand.tool-binding.json" \
    "$cand" "$rustv" "$SENTINEL" "$tools" "$builder" "$src" <<'PY'
import json, sys, hashlib
(decl_path, bind_path, cand, rustv, sentinel, tools, builder, src) = sys.argv[1:9]
proof, bindings = [], []
for spec in tools.split(","):
    name, ver = spec.split(":")
    declared = hashlib.sha256(f"{sentinel}-{name}-{ver}".encode()).hexdigest()
    installed = hashlib.sha256(f"{sentinel}-installed-{name}-{ver}".encode()).hexdigest()
    ident = f"{sentinel}://{name}-{ver}"
    entry = f"{sentinel}:cargo:{name}@{ver}"
    proof.append({
        "name": name, "version": ver, "artifact_identity": ident,
        "checksum_algorithm": "sha256", "checksum_hex": declared,
        "install_entrypoint": entry,
    })
    bindings.append({
        "candidate": cand, "name": name, "version": ver, "artifact_identity": ident,
        "checksum_algorithm": "sha256", "declared_checksum_hex": declared,
        "verified_artifact_hex": declared, "installed_binary_sha256_hex": installed,
        "install_entrypoint": entry, "container_digest": builder,
        "source_commit": src, "test_only": True,
    })
# The declaration is a PROJECTION of the (synthetic) verified bindings.
with open(decl_path, "w") as f:
    json.dump({"candidate": cand, "rust_version": rustv, "proof_tools": proof}, f, indent=2)
    f.write("\n")
with open(bind_path, "w") as f:
    json.dump(bindings, f, indent=2)
    f.write("\n")
PY
}

if is_dryrun; then
  emit_dry Sp1  "$RUST" "sp1-verifier:$SP1_VER"
  emit_dry Risc0 "$RUST" "risc0-zkvm:$R0_ZKVM,risc0-groth16:$R0_G16"
  note "wrote SYNTHETIC (sentinel-marked) $out/{Sp1,Risc0}.{tool,tool-binding}.json"
  exit 0
fi

# AUTHORITATIVE: download -> verify checksum -> install -> verify binary -> bind, per
# declared proof tool. Absent owner metadata / bindings is fail-closed; nothing invented.
[ -n "${SP1_TOOL_IDENTITY:-}" ]   || nyr "SP1_TOOL_IDENTITY (owner-supplied real installer metadata) is required"
[ -n "${RISC0_TOOL_IDENTITY:-}" ] || nyr "RISC0_TOOL_IDENTITY (owner-supplied real installer metadata) is required"
[ -f "$SP1_TOOL_IDENTITY" ]   || die "SP1_TOOL_IDENTITY file $SP1_TOOL_IDENTITY not found"
[ -f "$RISC0_TOOL_IDENTITY" ] || die "RISC0_TOOL_IDENTITY file $RISC0_TOOL_IDENTITY not found"
require_full_sha256_digest SP1_BUILDER_DIGEST "${SP1_BUILDER_DIGEST:-}"
require_full_sha256_digest RISC0_BUILDER_DIGEST "${RISC0_BUILDER_DIGEST:-}"
[ -n "${SOURCE_COMMIT:-}" ] || nyr "SOURCE_COMMIT (clean source commit the run is bound to) is required"
require_cmd curl

VAL="$ROOT/../b0-pre-validator/Cargo.toml"
[ -f "$VAL" ] || die "missing validator manifest $VAL"

# Verify + bind every proof tool the owner metadata declares for one candidate, and
# emit the AUTHORITATIVE binding record + a derived declaration.
process_candidate() {
  local cand="$1" meta="$2" builder="$3"
  local n; n="$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["proof_tools"]))' "$meta")"
  [ "$n" -ge 1 ] || die "$cand tool metadata declares no proof tools"
  local i=0
  : > "$out/$cand.bindings.ndjson"
  while [ "$i" -lt "$n" ]; do
    local declared="$out/$cand.tool.$i.declared.json"
    python3 - "$meta" "$i" "$declared" <<'PY'
import json, sys
meta, i, out = sys.argv[1], int(sys.argv[2]), sys.argv[3]
t = json.load(open(meta))["proof_tools"][i]
json.dump({k: t[k] for k in
           ("name","version","artifact_identity","checksum_algorithm","checksum_hex","install_entrypoint")},
          open(out, "w"))
PY
    local url entry
    url="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["artifact_identity"])' "$declared")"
    entry="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["install_entrypoint"])' "$declared")"

    # Download the exact declared artifact.
    local artifact="$out/$cand.tool.$i.artifact.bin"
    curl -fsSL "$url" -o "$artifact" || die "download of declared artifact failed: $url"

    # Install via the owner-declared entrypoint (run on the venue) and locate the
    # installed binary at the operator-provided path. Absent = fail closed.
    local installed="$out/$cand.tool.$i.installed.bin"
    TOOL_INSTALL_DEST="$installed" sh -c "$entry" || die "install entrypoint failed for $cand tool $i"
    [ -s "$installed" ] || die "installed binary not produced at $installed; refusing to bind an unverified tool"

    # Verify the declared checksum over the artifact bytes + BIND both hashes.
    cargo run --quiet --locked --manifest-path "$VAL" --bin venue-verify -- \
      verify-tool authoritative "$declared" "$artifact" "$installed" \
      > "$out/$cand.tool.$i.binding.json" \
      || die "tool checksum-verify / binary-binding failed for $cand tool $i"

    # Compose the AUTHORITATIVE ToolBindingRecord (verified hashes + container/source
    # binding), and stream it as one NDJSON line.
    python3 - "$declared" "$out/$cand.tool.$i.binding.json" "$cand" "$builder" "$SOURCE_COMMIT" \
      >> "$out/$cand.bindings.ndjson" <<'PY'
import json, sys
declared, binding, cand, builder, src = sys.argv[1:6]
d = json.load(open(declared)); b = json.load(open(binding))
rec = {
    "candidate": cand, "name": d["name"], "version": d["version"],
    "artifact_identity": d["artifact_identity"], "checksum_algorithm": d["checksum_algorithm"],
    "declared_checksum_hex": d["checksum_hex"], "verified_artifact_hex": b["verified_artifact_hex"],
    "installed_binary_sha256_hex": b["installed_binary_sha256_hex"],
    "install_entrypoint": d["install_entrypoint"], "container_digest": builder,
    "source_commit": src, "test_only": b["test_only"],
}
print(json.dumps(rec))
PY
    i=$((i + 1))
  done

  # The AUTHORITATIVE per-candidate tool entry: the verified binding records.
  python3 - "$out/$cand.bindings.ndjson" "$out/$cand.tool-binding.json" <<'PY'
import json, sys
recs = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
json.dump(recs, open(sys.argv[2], "w"), indent=2)
open(sys.argv[2], "a").write("\n")
PY

  # The Stage-6 declaration, DERIVED from the verified bindings (never an owner copy).
  python3 - "$meta" "$out/$cand.tool-binding.json" "$out/$cand.tool.json" "$cand" <<'PY'
import json, sys
meta = json.load(open(sys.argv[1]))
bindings = json.load(open(sys.argv[2]))
proof = [{
    "name": b["name"], "version": b["version"], "artifact_identity": b["artifact_identity"],
    "checksum_algorithm": b["checksum_algorithm"], "checksum_hex": b["declared_checksum_hex"],
    "install_entrypoint": b["install_entrypoint"],
} for b in bindings]
json.dump({"candidate": sys.argv[4], "rust_version": meta["rust_version"], "proof_tools": proof},
          open(sys.argv[3], "w"), indent=2)
open(sys.argv[3], "a").write("\n")
PY
  note "verified + bound $n proof tool(s) for $cand -> $out/$cand.tool-binding.json (authoritative entry) + derived $cand.tool.json"
}

process_candidate Sp1   "$SP1_TOOL_IDENTITY"   "$SP1_BUILDER_DIGEST"
process_candidate Risc0 "$RISC0_TOOL_IDENTITY" "$RISC0_BUILDER_DIGEST"
