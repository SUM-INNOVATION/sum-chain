#!/usr/bin/env bash
# Produce (or verify) the ONE sealed B0-FINAL measurement-input authority package.
#
# This is the pre-grid generator for the MeasurementInputAuthorityV1 correction: it REPLACES the three
# former caller-supplied hashes (RSS_CONTEXT_HASH, MALFORMED_CORPUS_RESULT_HASH, HARNESS_SOURCE_HASH)
# with a single retained, content-addressed authority whose two data legs are RECOMPUTED from retained
# bytes — never operator-supplied 64-hex strings:
#
#   * malformed-corpus report : the b0-pre-malformed-corpus generator runs a FIXED ordered corpus
#                               through the real guest/verifier boundary (b0_pre_guest_core::run) and
#                               emits a SHA-256 domain-addressed report retaining every member's exact
#                               bytes + the stable GuestError discriminant/class (never display text).
#   * harness-source inventory: b0-pre-host-provenance --emit-harness-inventory computes the canonical
#                               causal source-closure inventory (relative path, mode/size, BLAKE3) from
#                               the CLEAN tooling root and returns BLAKE3(domain‖manifest).
#
# The MeasurementInputAuthorityV1 JSON binds BOTH recomputed addresses + the spec/workload identity +
# the measured-source + tooling identity + the RSS statement-binding policy, and is SHA-256 addressed.
# The sealed package's three members travel byte-identical in every measurement fragment; both verifiers
# re-decode + recompute all three addresses; measure-produce --verify-authority ties the tooling
# commit/path-set to RATIFIED as a fail-fast pre-grid gate.
#
# Usage:
#   produce_measurement_input_authority.sh produce <measured-root> <tooling-root> <official.json> <out-pkg-dir>
#   produce_measurement_input_authority.sh verify  <package-dir>
#
# Required env:
#   MALFORMED_CORPUS_BIN   # repo-built b0-pre-malformed-corpus
#   PROV_BIN               # repo-built b0-pre-host-provenance (--emit-harness-inventory)
#   MEASURE_PRODUCE        # repo-built measure-produce (verify delegates to --verify-authority)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
# shellcheck source=lib.sh
. "$HERE/lib.sh"
# shellcheck source=two_root_authority.sh
. "$HERE/two_root_authority.sh"

MIA_SCHEMA='b0-final-measurement-input-authority/v1'
ELIG_SCHEMA='b0-final-eligibility-matrix/v1'
RSS_POLICY='per-cell-statement/v1'
MERGED_SPEC='e933e7325c2639a48d8e25f20746d0f8abc822dee9fcfa87c2e6cdec226cf2a2'
MIA_JSON_NAME='measurement-input-authority.v1.json'
REPORT_JSON_NAME='malformed-corpus-report.v1.json'
INVENTORY_TXT_NAME='harness-source-inventory.txt'
ELIG_JSON_NAME='eligibility-matrix.v1.json'
# package content-address domain (member set integrity of the sealed dir).
MIA_PKG_DOMAIN='b0-final-measurement-input-authority-package/v1'

b3() { b3sum "$1" | awk '{print $1}'; }
die() { echo "REFUSED: $*" >&2; exit 1; }
note() { echo "[measurement-input-authority] $*" >&2; }

MODE="${1:-}"; shift || true

# package content address: DOMAIN\0 + sorted "<member_blake3>  <relpath>" -> b3sum
mia_package_address() { # <package-dir>
  local dir="$1" man
  man="$(cd "$dir" && find . -type f ! -name '.content-address' | LC_ALL=C sort \
    | while IFS= read -r f; do printf '%s  %s\n' "$(b3 "$f")" "${f#./}"; done)"
  { printf '%s\0' "$MIA_PKG_DOMAIN"; printf '%s' "$man"; } | b3sum | awk '{print $1}'
}

produce() {
  local MSRC="${1:-}" TSRC="${2:-}" OFFICIAL="${3:-}" OUT="${4:-}"
  [ -n "$MSRC" ] && [ -n "$TSRC" ] && [ -n "$OFFICIAL" ] && [ -n "$OUT" ] \
    || die "usage: produce <measured-root> <tooling-root> <official.json> <out-pkg-dir>"
  [ -s "$OFFICIAL" ] || die "official workload JSON absent/empty: $OFFICIAL"
  [ -n "${MALFORMED_CORPUS_BIN:-}" ] && [ -x "$MALFORMED_CORPUS_BIN" ] || die "MALFORMED_CORPUS_BIN (b0-pre-malformed-corpus) required + executable"
  [ -n "${PROV_BIN:-}" ] && [ -x "$PROV_BIN" ] || die "PROV_BIN (b0-pre-host-provenance) required + executable"
  require_cmd b3sum; require_cmd sha256sum; require_cmd python3

  # Two-root authority: measured HEAD == RATIFIED_SOURCE_COMMIT (clean), tooling clean/non-nested. The
  # authority binds the MEASURED source commit and the TOOLING commit/path-set (the gate later ties the
  # tooling identity to RATIFIED, refusing a stale package after subsequent source edits).
  require_two_roots --measured-source-root "$MSRC" --tooling-root "$TSRC"
  export B0_MEASURED_ROOT B0_MEASURED_COMMIT B0_TOOLING_ROOT B0_TOOLING_COMMIT B0_TOOLING_PATHSET_BLAKE3

  rm -rf "$OUT"; mkdir -p "$OUT"
  local report="$OUT/$REPORT_JSON_NAME" inv="$OUT/$INVENTORY_TXT_NAME" mia="$OUT/$MIA_JSON_NAME"

  # ---- malformed-corpus report: fixed ordered corpus through the REAL guest boundary ----
  note "generating malformed-corpus report (real guest/verifier boundary)"
  "$MALFORMED_CORPUS_BIN" --official "$OFFICIAL" --spec-hash "$MERGED_SPEC" \
    --measured-source-commit "$B0_MEASURED_COMMIT" --tooling-commit "$B0_TOOLING_COMMIT" \
    --tooling-pathset-blake3 "$B0_TOOLING_PATHSET_BLAKE3" --out "$report" \
    || die "malformed-corpus report generation failed (a corpus member's actual GuestError class != expected)"
  [ -s "$report" ] || die "malformed-corpus report is empty"
  local report_addr; report_addr="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["address"])' "$report")"
  printf '%s' "$report_addr" | grep -Eq '^[0-9a-f]{64}$' || die "malformed-corpus report address malformed"

  # ---- harness-source inventory: canonical causal source closure from the CLEAN tooling root ----
  note "computing harness-source inventory from the clean tooling root"
  local inv_addr
  inv_addr="$("$PROV_BIN" --emit-harness-inventory --tooling-root "$B0_TOOLING_ROOT" --out "$inv")" \
    || die "harness-source inventory computation failed (incomplete/dirty tooling source closure)"
  [ -s "$inv" ] || die "harness-source inventory manifest is empty"
  printf '%s' "$inv_addr" | grep -Eq '^[0-9a-f]{64}$' || die "harness-source inventory address malformed"

  # ---- eligibility/unsupported matrix: the FROZEN ratified two-cell declaration ----
  # (3 identity cells, 2 native-measurement cells, exact unsupported set). Entry values are FROZEN and
  # MUST match measurement::eligibility_matrix::EligibilityMatrixV1::canonical byte-for-byte; the address
  # is SHA-256 over the same NUL-joined preimage recompute_address() builds. Both verifiers re-decode +
  # recompute it, and the MIA below binds its address.
  local elig="$OUT/$ELIG_JSON_NAME"
  python3 - "$elig" "$ELIG_SCHEMA" "$MERGED_SPEC" <<'PY' || die "eligibility matrix assembly failed"
import json, sys, hashlib
out, schema, spec = sys.argv[1:4]
# FROZEN rows — exactly the ratified two-cell model (order is canonical + FROZEN).
rows = [
    ("Sp1","x86_64",True,True,"","sp1-recursion-gnark-ffi/docker","sp1-gnark:v6.1.0","",""),
    ("Sp1","aarch64",True,False,"sp1-aarch64-groth16-no-arm-backend",
     "sp1-recursion-gnark-ffi/docker","sp1-gnark:v6.1.0",
     "oci-index sha256:e1a1cd62 publishes only linux/amd64; no linux/arm64 manifest",
     "arm-sp1-stage5 no-arm-gnark-evidence (CONFIRMED); B0-FINAL eligibility matrix"),
    ("Risc0","x86_64",True,True,"","risc0-groth16","risc0-zkvm:3.0.5","",""),
    ("Risc0","aarch64",False,False,"risc0-aarch64-x86-only","risc0-groth16","risc0-zkvm:3.0.5",
     "RISC Zero r0vm/cargo-risczero published x86_64-only (VENUE section 2)",
     "B0-FINAL eligibility matrix; VENUE.md section 2"),
]
entries = []
for (c,a,idn,meas,reason,backend,ver,evid,auth) in rows:
    entries.append(dict(candidate=c, arch=a, identity_eligible=idn,
        native_measurement_eligible=meas, unsupported=(not meas), reason_code=reason,
        backend=backend, backend_version=ver, arch_manifest_evidence=evid, governing_authority=auth))
# Rust bool.to_string() == "true"/"false"; entries.len().to_string() == "4".
def b(x): return "true" if x else "false"
parts = [schema, spec, str(len(entries))]
for e in entries:
    parts += [e["candidate"], e["arch"], b(e["identity_eligible"]),
              b(e["native_measurement_eligible"]), b(e["unsupported"]), e["reason_code"],
              e["backend"], e["backend_version"], e["arch_manifest_evidence"], e["governing_authority"]]
addr = hashlib.sha256("\0".join(parts).encode()).hexdigest()
rec = dict(schema=schema, b0_pre_spec_hash=spec, entries=entries, address=addr)
# compact form (matches EligibilityMatrixV1::to_json — serde_json::to_string).
open(out, "w", encoding="utf-8").write(json.dumps(rec, separators=(",", ":")) + "\n")
PY
  [ -s "$elig" ] || die "eligibility matrix record is empty"
  local elig_addr; elig_addr="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["address"])' "$elig")"
  printf '%s' "$elig_addr" | grep -Eq '^[0-9a-f]{64}$' || die "eligibility matrix address malformed"

  # ---- assemble + SHA-256 address the unified MeasurementInputAuthorityV1 ----
  python3 - "$mia" "$MIA_SCHEMA" "$MERGED_SPEC" "$B0_MEASURED_COMMIT" "$B0_TOOLING_COMMIT" \
    "$B0_TOOLING_PATHSET_BLAKE3" "$inv_addr" "$report_addr" "$RSS_POLICY" "$elig_addr" <<'PY' || die "MIA assembly failed"
import json, sys, hashlib
out, schema, spec, measured, tcommit, tpathset, inv_addr, report_addr, policy, elig_addr = sys.argv[1:11]
f = dict(
    schema=schema, b0_pre_spec_hash=spec, measured_source_commit=measured,
    tooling_commit=tcommit, tooling_pathset_blake3=tpathset,
    harness_source_inventory_address=inv_addr, malformed_corpus_report_address=report_addr,
    rss_statement_binding_policy=policy, eligibility_matrix_address=elig_addr,
)
# address = SHA-256 over the canonical NUL-joined preimage (matches venue::sha256::hex_digest and the
# independent crate's own SHA-256 recompute). Field order is FROZEN — mirrors recompute_address()
# (eligibility_matrix_address is the LAST field before hashing).
pre = "\0".join([
    f["schema"], f["b0_pre_spec_hash"], f["measured_source_commit"],
    f["tooling_commit"], f["tooling_pathset_blake3"],
    f["harness_source_inventory_address"], f["malformed_corpus_report_address"],
    f["rss_statement_binding_policy"], f["eligibility_matrix_address"],
])
f["address"] = hashlib.sha256(pre.encode()).hexdigest()
# pretty, stable key order matching the fixture (schema-first, address-last).
json.dump(f, open(out, "w", encoding="utf-8"), indent=2)
open(out, "a", encoding="utf-8").write("\n")
PY
  local mia_addr; mia_addr="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["address"])' "$mia")"

  # ---- seal the package content-address (member-set integrity) ----
  local pkg_addr; pkg_addr="$(mia_package_address "$OUT")"
  printf '%s\n' "$pkg_addr" > "$OUT/.content-address"

  note "sealed MeasurementInputAuthorityV1 package -> $OUT"
  note "  authority_address   = $mia_addr"
  note "  inventory_address   = $inv_addr"
  note "  report_address      = $report_addr"
  note "  eligibility_address = $elig_addr"
  note "  package_address     = $pkg_addr"
  echo "$mia_addr"
}

verify() { # <package-dir>  — delegates the decode + cross-bind + tooling==RATIFIED gate to measure-produce.
  local PKG="${1:-}"; [ -d "$PKG" ] || die "usage: verify <package-dir>"
  [ -n "${MEASURE_PRODUCE:-}" ] && [ -x "$MEASURE_PRODUCE" ] || die "MEASURE_PRODUCE required + executable for verify"
  require_cmd b3sum
  local mia="$PKG/$MIA_JSON_NAME" report="$PKG/$REPORT_JSON_NAME" inv="$PKG/$INVENTORY_TXT_NAME" elig="$PKG/$ELIG_JSON_NAME"
  for f in "$mia" "$report" "$inv" "$elig"; do [ -s "$f" ] || die "package missing/empty member: $f"; done
  # member-set integrity.
  local recomputed stored
  recomputed="$(mia_package_address "$PKG")"
  stored="$(cat "$PKG/.content-address" 2>/dev/null || true)"
  [ -n "$stored" ] && [ "$stored" != "$recomputed" ] \
    && die "package content address mismatch (member set tampered): stored=$stored recomputed=$recomputed"
  # decode + cross-bind (incl. eligibility) + tooling==RATIFIED (the same fail-fast gate the venue runs pre-grid).
  "$MEASURE_PRODUCE" --verify-authority "$mia" "$report" "$inv" "$elig" >&2 \
    || die "measurement-input authority failed decode/cross-bind/tooling-ratified verification"
  note "verified MeasurementInputAuthorityV1 package $PKG (package_address=$recomputed)"
}

case "$MODE" in
  produce) produce "$@" ;;
  verify)  verify "$@" ;;
  *) die "mode must be produce|verify" ;;
esac
