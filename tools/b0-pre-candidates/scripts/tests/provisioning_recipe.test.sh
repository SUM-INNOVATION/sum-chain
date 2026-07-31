#!/usr/bin/env bash
# OFF-VENUE structural contract for the declarative AUDIT + PROVER provisioning (Items 2/3/4/7).
# The Docker builds themselves are venue-gated (native x86 + real archives + the advisory-DB
# checkout), so this test does NOT build any image. It LOCKS the reviewable structure that the
# venue build then executes, and fails closed on a regression that would silently reintroduce a
# forbidden mechanism (`rzup`, `curl | tar`, a copied host cargo-audit, an unverified extraction)
# or drop a reproducibility / fail-closed guard. Pure filesystem + grep; no Docker, no toolchain.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCR="$(cd "$HERE/.." && pwd)"
CONT="$(cd "$SCR/../containers" && pwd)"
SP1="$CONT/sp1.Dockerfile"; R0="$CONT/risc0.Dockerfile"
PROV="$SCR/provision_prover_toolchain.sh"
F=0; ok(){ printf 'ok    %s\n' "$1"; }; bad(){ printf 'FAIL  %s\n' "$1" >&2; F=1; }
has(){ grep -Eq "$2" "$1"; }             # file, ERE
hasnt(){ ! grep -Eq "$2" "$1"; }          # file, ERE (must be ABSENT)
# CODE-only variants: strip `#` comment lines first, so the header comments that legitimately
# NAME the forbidden mechanisms ("NO rzup", "NO curl | tar") do not create false positives.
has_code(){ grep -v '^[[:space:]]*#' "$1" | grep -Eq "$2"; }
hasnt_code(){ ! grep -v '^[[:space:]]*#' "$1" | grep -Eq "$2"; }

# ---- 1. The single tested provisioner is STAGED byte-identically into the curated context
#         (owner ruling: no second implementation; the Dockerfiles COPY this exact file).
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
if bash "$SCR/stage_context.sh" sp1 "$T/ctx" >/dev/null 2>&1 \
   && [ -f "$T/ctx/provisioning/provision_prover_toolchain.sh" ] \
   && diff -q "$PROV" "$T/ctx/provisioning/provision_prover_toolchain.sh" >/dev/null; then
  ok "stage_context stages provisioning/provision_prover_toolchain.sh IDENTICAL to the tested source"
else
  bad "stage_context did not stage the provisioner identically (second-implementation / drift risk)"
fi
# isolation preserved: no Cargo.lock, no unrelated crate leaked by adding the provisioner.
if [ -z "$(find "$T/ctx" -name Cargo.lock 2>/dev/null)" ]; then ok "no Cargo.lock leaked into the staged context"; else bad "a Cargo.lock leaked into the staged context"; fi

# ---- 2. Forbidden mechanisms are ABSENT from BOTH Dockerfiles.
for df in "$SP1" "$R0"; do
  b="$(basename "$df")"
  hasnt_code "$df" 'rzup'                       && ok "$b: no rzup (code)"           || bad "$b: rzup is forbidden"
  hasnt_code "$df" 'curl[^|]*\|[^|]*tar'        && ok "$b: no 'curl | tar' pipe (code)" || bad "$b: 'curl | tar' is forbidden (use the verified extractor)"
  # cargo-audit is BUILT here, never a copied host binary.
  hasnt_code "$df" 'COPY[[:space:]]+[^[:space:]]*cargo-audit' && ok "$b: does not COPY a host cargo-audit binary" || bad "$b: must not COPY a host cargo-audit"
  has_code "$df" 'cargo install --locked --path' && ok "$b: cargo-audit built with 'cargo install --locked --path'" || bad "$b: cargo-audit must be built --locked from the verified crate path"
done

# ---- 3. cargo-audit build-in-builder (Item 4): verify crate + packaged-lock BEFORE build,
#         record exe sha as venue evidence, remove scratch in the same layer.
for df in "$SP1" "$R0"; do
  b="$(basename "$df")"
  has "$df" 'CARGO_AUDIT_CRATE_SHA256.*grep -Eq'                    && ok "$b: cargo-audit crate sha256 shape-checked" || bad "$b: cargo-audit crate sha256 not validated"
  has "$df" 'CARGO_AUDIT_CRATE_SHA256.*sha256sum -c'               && ok "$b: cargo-audit crate verified pre-extract" || bad "$b: cargo-audit crate not verified before extraction"
  has "$df" 'CARGO_AUDIT_PACKAGED_LOCK_SHA256.*sha256sum -c'       && ok "$b: packaged Cargo.lock verified"           || bad "$b: packaged Cargo.lock not verified"
  has "$df" 'static\.crates\.io/crates/cargo-audit/cargo-audit-'  && ok "$b: cargo-audit crate URL pinned to immutable crates.io path" || bad "$b: cargo-audit crate URL not pinned"
  has "$df" 'evidence/cargo-audit\.exe\.sha256'                    && ok "$b: cargo-audit exe sha recorded as venue evidence" || bad "$b: cargo-audit exe sha not recorded"
  has "$df" 'rm -rf /tmp/ca-build'                                 && ok "$b: cargo-audit build scratch removed in-layer" || bad "$b: cargo-audit scratch not removed in-layer"
done

# ---- 3b. Reproducibility: the cargo-audit RUN layer deletes EXACTLY cargo's disposable
#          /root/.cargo/.global-cache (the SQLite cache-GC tracker that embeds wall-clock last-use
#          timestamps — the sole divergent byte source at SP1 two-clean-build equality), AFTER the
#          last cargo op in the layer, WITHOUT a broad /root/.cargo sweep and WITHOUT removing the
#          toolchain, audit-prefix, or the installed cargo-audit.
for df in "$SP1" "$R0"; do
  b="$(basename "$df")"
  has_code "$df" 'rm -f /root/\.cargo/\.global-cache' && ok "$b: removes exactly /root/.cargo/.global-cache" || bad "$b: missing exact .global-cache removal"
  # the removal is AFTER the last 'cargo install' (the last cargo op) in the layer.
  ci_line="$(grep -nE 'cargo install --locked --path' "$df" | tail -1 | cut -d: -f1)"
  gc_line="$(grep -nE 'rm -f /root/\.cargo/\.global-cache' "$df" | tail -1 | cut -d: -f1)"
  if [ -n "$ci_line" ] && [ -n "$gc_line" ] && [ "$gc_line" -gt "$ci_line" ]; then
    ok "$b: .global-cache removal (line $gc_line) is AFTER the cargo install (line $ci_line)"
  else
    bad "$b: .global-cache removal not proven after the last cargo op (ci=$ci_line gc=$gc_line)"
  fi
  # NO broad /root/.cargo sweep, NO wildcard, toolchain + audit-prefix + cargo-audit KEPT.
  hasnt_code "$df" 'rm [^;]*/root/\.cargo([^/.]|$)' && ok "$b: no bare/broad /root/.cargo removal" || bad "$b: broad /root/.cargo removal present"
  hasnt_code "$df" '/root/\.cargo/\*'               && ok "$b: no /root/.cargo/* wildcard"        || bad "$b: /root/.cargo/* wildcard present"
  hasnt_code "$df" 'rm[^;]*/root/\.cargo/bin'       && ok "$b: keeps /root/.cargo/bin (toolchain)" || bad "$b: removes the toolchain bin"
  hasnt_code "$df" 'rm[^;]*/opt/b0pre/audit-prefix' && ok "$b: keeps /opt/b0pre/audit-prefix + cargo-audit" || bad "$b: removes the audit prefix"
done

# ---- 4. Prover provisioning via the STAGED verified extractor (Items 2/3).
has "$SP1" 'COPY provisioning/provision_prover_toolchain\.sh' && ok "sp1: COPYs the staged provisioner"   || bad "sp1: does not COPY the staged provisioner"
has "$R0"  'COPY provisioning/provision_prover_toolchain\.sh' && ok "risc0: COPYs the staged provisioner" || bad "risc0: does not COPY the staged provisioner"
has "$SP1" 'bash /usr/local/lib/b0pre/provision_prover_toolchain\.sh' && ok "sp1: runs the staged extractor (bash)" || bad "sp1: extractor not invoked"
has "$SP1" 'SP1_ARCHIVE_SHA256'                                      && ok "sp1: extractor fed the verified SP1 archive sha" || bad "sp1: archive sha not referenced"
has "$SP1" 'CARGO_PROVE_MEMBER_PATH.*:isolated'                 && ok "sp1: cargo-prove delivered isolated"  || bad "sp1: cargo-prove delivery not isolated"
has "$R0"  'CARGO_RISCZERO_MEMBER_PATH.*:isolated'              && ok "risc0: cargo-risczero delivered isolated" || bad "risc0: cargo-risczero delivery not isolated"
has "$R0"  'R0VM_MEMBER_PATH.*:risc0server'                     && ok "risc0: r0vm delivered risc0server"    || bad "risc0: r0vm delivery not risc0server"

# ---- 5. RISC Zero is x86_64-only (VENUE.md §2) + canonical RISC0_SERVER_PATH.
has "$R0" 'uname -m.*!=.*x86_64|x86_64.*RISC Zero|SKIP RISC Zero' && ok "risc0: RISC Zero provisioning guarded x86_64-only" || bad "risc0: missing x86_64-only guard"
has "$R0" 'ENV RISC0_SERVER_PATH="/opt/b0pre/risc0-server/r0vm"'  && ok "risc0: ENV RISC0_SERVER_PATH set to the canonical path" || bad "risc0: RISC0_SERVER_PATH not set"
hasnt "$SP1" 'RISC0_ARCHIVE' && ok "sp1: does not carry RISC Zero prover args" || bad "sp1: unexpectedly references RISC Zero"

# ---- 6. Prover exe shas recorded as evidence + archive scratch removed in-layer (Item 7).
has "$SP1" 'evidence/cargo-prove\.exe\.sha256'     && ok "sp1: cargo-prove exe sha recorded"     || bad "sp1: cargo-prove exe sha not recorded"
has "$R0"  'evidence/cargo-risczero\.exe\.sha256'  && ok "risc0: cargo-risczero exe sha recorded" || bad "risc0: cargo-risczero exe sha not recorded"
has "$R0"  'evidence/r0vm\.exe\.sha256'            && ok "risc0: r0vm exe sha recorded"           || bad "risc0: r0vm exe sha not recorded"
for df in "$SP1" "$R0"; do
  b="$(basename "$df")"
  has "$df" 'rm -rf /tmp/prov' && ok "$b: prover archive scratch removed in-layer" || bad "$b: prover scratch not removed in-layer"
done

# ---- 7. build_container.sh gates the new pins fail-closed (nyr) + passes the build-args.
BC="$SCR/build_container.sh"
has "$BC" 'CARGO_AUDIT_VERSION.*nyr'      && ok "build_container: cargo-audit pins gated NOT_YET_REPRODUCED" || bad "build_container: cargo-audit pins not gated"
has "$BC" 'SP1_ARCHIVE_URL.*nyr'          && ok "build_container: SP1 prover pins gated (sp1)"                || bad "build_container: SP1 prover pins not gated"
has "$BC" 'RISC0_ARCHIVE_URL.*nyr'        && ok "build_container: RISC Zero prover pins gated (risc0 x86)"    || bad "build_container: RISC Zero prover pins not gated"
has "$BC" 'build-arg "CARGO_AUDIT_VERSION' && ok "build_container: passes cargo-audit build-arg"              || bad "build_container: does not pass cargo-audit build-arg"
has "$BC" 'build-arg "SP1_ARCHIVE_URL'    && ok "build_container: passes SP1 prover build-arg"                || bad "build_container: does not pass SP1 prover build-arg"
has "$BC" 'build-arg "R0VM_MEMBER_SHA256' && ok "build_container: passes r0vm build-arg"                      || bad "build_container: does not pass r0vm build-arg"

# ---- 8. lib.sh carries the prover-capability preflight + stages the provisioner.
LIB="$SCR/lib.sh"
has "$LIB" 'preflight_prover_capability\(\)'                        && ok "lib.sh: preflight_prover_capability present" || bad "lib.sh: preflight_prover_capability missing"
has "$LIB" 'cp .*scripts/provision_prover_toolchain\.sh.*provisioning' && ok "lib.sh: stage_container_context stages the provisioner" || bad "lib.sh: provisioner not staged"

echo "----"
if [ "$F" = 0 ]; then echo "PROVISIONING_RECIPE_PASS"; echo "provisioning_recipe: ALL TESTS PASS"; exit 0
else echo "provisioning_recipe: FAILURE(S)" >&2; exit 1; fi
