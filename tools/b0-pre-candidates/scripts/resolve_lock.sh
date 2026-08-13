#!/usr/bin/env bash
# Materialize the COMMITTED candidate Cargo.lock for one candidate, copied out to the
# workdir as the Stage-6 lock input (<Candidate>.Cargo.lock), together with its
# committed-source-of-truth PROVENANCE.
#
# DEPENDENCY-SELECTION AUTHORITY (owner ruling): after a candidate `Cargo.lock` is
# committed it IS the exact, frozen dependency graph. The authoritative venue does NOT
# re-resolve it. It copies the committed lock into the isolated candidate workspace inside
# the pinned builder image and MATERIALIZES that exact graph under Cargo LOCKED semantics
# (`cargo vendor --locked`, `cargo metadata --locked`), mounting the committed lock
# READ-ONLY. It NEVER runs `cargo generate-lockfile` or any unlocked command that could
# reselect a newer semver-compatible release from a moving registry — that is the defect
# this path was corrected to remove (an unconstrained regenerate selected
# `http-body-util 0.1.5` against a committed graph pinned to `0.1.4`). The committed lock is
# required byte-identical before and after every Cargo operation.
#
# Blocker 2 (host-lock rejection): a host-supplied lock is refused. The lock is the COMMITTED
# one; its recorded SHA-256 and domain-separated BLAKE3 are recomputed from the committed
# bytes and independently re-verified by `venue-verify verify-lock` (which recomputes them
# again, checks origin = committed-source-of-truth, and rejects a mutated lock or any
# mismatch). Off-venue (no Docker/builder image) this fails closed.
#
# OFF-VENUE dry run (SUMCHAIN_B0PRE_DRYRUN=1) writes a real-SHAPED sample lock so the
# compatibility test can hash a lock without a container.
#
# Usage: resolve_lock.sh <sp1|risc0> <out_dir>
# Required env (authoritative): BUILDER_IMAGE_REF, BUILDER_IMAGE_DIGEST (sha256:...),
#                               SCHEMA_ARCH (X86_64|Aarch64).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
# shellcheck source=lib.sh
. "$HERE/lib.sh"

candidate="${1:-}"; out="${2:-}"
case "$candidate" in sp1|risc0) ;; *) die "candidate must be sp1|risc0 (got '${candidate:-}')" ;; esac
[ -n "$out" ] || die "output directory argument required"
mkdir -p "$out"
case "$candidate" in sp1) schema_cand=Sp1 ;; risc0) schema_cand=Risc0 ;; esac
dest="$out/$schema_cand.Cargo.lock"

if is_dryrun; then
  {
    printf '# TEST_ONLY synthetic %s Cargo.lock (dry-run sample; not a real lock)\n' "$schema_cand"
    printf 'version = 3\n'
  } > "$dest"
  note "wrote SYNTHETIC $dest"
  # The synthetic lock has no [[package]] rows, so the third-party notice set is trivially empty;
  # emit it (no vendoring) + a minimal synthetic target-closure so the shared assembler always finds
  # the required per-candidate files.
  VAL="$ROOT/../b0-pre-validator/Cargo.toml"
  dry_arch="${SCHEMA_ARCH:-X86_64}"
  dry_lockhex="$(cargo run --quiet --locked --manifest-path "$VAL" --bin venue-verify -- lock-hash "$dest")" \
    || die "dry-run lock-hash failed for $dest"
  dry_closure="$out/$schema_cand.target-closure.json"
  python3 - "$dry_closure" "$schema_cand" "$dry_arch" "$dry_lockhex" <<'PY'
import json, sys
out, cand, arch, lockhash = sys.argv[1:5]
US = "\x1f"
json.dump({"schema_version": 1, "candidate": cand, "arch": arch,
           "venue_targets": ["x86_64-unknown-linux-gnu"], "features": [],
           "lock_blake3_hex": lockhash, "stage2_graph_blake3_hex": lockhash,
           "roots": [f"synthetic-root{US}0.0.0{US}"],
           "nodes": [{"name": "synthetic-root", "version": "0.0.0", "source": "", "normal_deps": []}]},
          open(out, "w"), indent=1)
PY
  cargo run --quiet --locked --manifest-path "$VAL" --bin venue-verify -- \
    notices-generate "$schema_cand" "$dry_arch" "$dry_lockhex" "$dest" /nonexistent-empty-graph-vendor \
    "$out/$schema_cand.third-party-notices.json" "$ROOT/policy/third-party-notice-map.json" "$dry_closure" >/dev/null \
    || die "dry-run notices-generate failed for $schema_cand"
  note "wrote SYNTHETIC $out/$schema_cand.third-party-notices.json + target-closure (empty graph)"
  exit 0
fi

# AUTHORITATIVE: the COMMITTED candidate Cargo.lock is the dependency-selection authority; a
# host-supplied lock is refused, and the lock is NEVER regenerated in-container.
[ -z "${SP1_CONTAINER_LOCK:-}${RISC0_CONTAINER_LOCK:-}" ] \
  || die "host-supplied lock env (SP1_CONTAINER_LOCK/RISC0_CONTAINER_LOCK) is refused; the committed candidate Cargo.lock is the authority"
require_linux_oci_builder
require_cmd b3sum
require_cmd python3
require_cmd docker
[ -n "${BUILDER_IMAGE_REF:-}" ] || nyr "BUILDER_IMAGE_REF (the pinned builder image the committed lock is materialized inside) is required"
require_full_sha256_digest BUILDER_IMAGE_DIGEST "${BUILDER_IMAGE_DIGEST:-}"
reject_placeholder BUILDER_IMAGE_DIGEST "${BUILDER_IMAGE_DIGEST:-}"
arch="${SCHEMA_ARCH:-}"
case "$arch" in X86_64|Aarch64) ;; *) die "SCHEMA_ARCH must be X86_64|Aarch64 (got '${arch:-}')" ;; esac
require_committed_lock "$ROOT/candidates/$candidate"
[ -z "$(git -C "$ROOT" status --porcelain 2>/dev/null || echo dirty)" ] \
  || die "source tree is not clean; refuse to resolve from a dirty state"
source_commit="$(git -C "$ROOT" rev-parse HEAD)"

VAL="$ROOT/../b0-pre-validator/Cargo.toml"
[ -f "$VAL" ] || die "missing validator manifest $VAL"

# The committed source-of-truth lock. Re-assert (defence in depth beyond require_committed_lock) it
# is a real, non-symlink, non-empty regular file at materialize time.
committed_lock="$ROOT/candidates/$candidate/Cargo.lock"
{ [ -f "$committed_lock" ] && [ ! -L "$committed_lock" ] && [ -s "$committed_lock" ]; } \
  || die "committed source-of-truth lock missing/symlink/empty: $committed_lock"

# (1) COPY the committed lock out as the Stage-6 lock input. The committed lock is the source of
#     truth; it is copied, never regenerated. The exported copy must be byte-identical.
cp "$committed_lock" "$dest"
cmp -s "$committed_lock" "$dest" \
  || die "exported lock is not byte-identical to the committed source-of-truth lock $committed_lock; refusing"

# (2) Record the committed lock IDENTITY BEFORE any Cargo runs: plain SHA-256 (sha256sum) and the
#     domain-separated BLAKE3 (the frozen lock identity). Both are recomputed from the committed
#     bytes by verify-lock; neither is trusted as a claim. lock_hex is THE candidate lock hash the
#     Stage-2 audit / notices / closure are all bound to.
pre_sha256="$(sha256_hex_stdin < "$committed_lock")"
is_bare_sha256 "$pre_sha256" || die "committed lock pre-run sha256 malformed: '$pre_sha256'"
lock_hex="$(cargo run --quiet --locked --manifest-path "$VAL" --bin venue-verify -- lock-hash "$committed_lock")" \
  || die "committed lock-hash (domain-separated BLAKE3) recomputation failed for $committed_lock"

# (3) The candidate workspace lives at its reproduced repo-relative path in the staged builder image
#     (see stage_context.sh); the committed lock is bind-mounted READ-ONLY at that workspace's
#     Cargo.lock so every `cargo … --locked` reproduces exactly the committed graph. Record the EXACT
#     locked-command log the materialization executes (vendor + per-target metadata). NO
#     `cargo generate-lockfile` and NO unlocked command is ever in this log.
#
# YANKED-VERSION NOTE (verified). The committed graph transitively pins `spin 0.9.9` (NON-yanked);
# `spin 0.9.8` — required only as an alternative for `lazy_static`'s optional `spin_no_std` feature —
# is yanked, but the committed lock already selected `0.9.9`, so `--locked` materialization neither
# needs nor reselects it. Regression: tools/b0-pre-validator/tests/candidate_lock_yanked_spin.rs.
cand_dir="$(incontainer_candidate_dir "$candidate")"
incontainer_lock="$cand_dir/Cargo.lock"
# Target-scoping: SP1 builds x86_64 + aarch64 Linux; RISC Zero x86_64 only. A crate outside the
# normal (runtime-linked) closure for these targets carries no notice.
case "$candidate" in
  sp1)   venue_targets="x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu" ;;
  risc0) venue_targets="x86_64-unknown-linux-gnu" ;;
esac
locked_cmd="$out/$schema_cand.materialize.locked.cmd"
{
  printf 'MATERIALIZE the COMMITTED candidate Cargo.lock under Cargo LOCKED semantics (candidate=%s, arch=%s)\n' "$candidate" "$arch"
  printf '# committed lock mounted READ-ONLY at %s; `cargo generate-lockfile` and every unlocked command are FORBIDDEN\n' "$incontainer_lock"
  printf 'docker run --rm --pull never --mount type=bind,source=<committed_Cargo.lock>,target=%s,readonly %s bash -c "cd %s && cargo vendor --locked --versioned-dirs /tmp/b0pre-vendor"\n' \
    "$incontainer_lock" "$BUILDER_IMAGE_DIGEST" "$cand_dir"
  for t in $venue_targets; do
    printf 'docker run --rm --pull never --mount type=bind,source=<committed_Cargo.lock>,target=%s,readonly %s bash -c "cd %s && cargo metadata --locked --filter-platform %s --format-version 1"\n' \
      "$incontainer_lock" "$BUILDER_IMAGE_DIGEST" "$cand_dir" "$t"
  done
} > "$locked_cmd"
cmdlog_hex="$(blake3_hex_file "$locked_cmd")"

# (4) MATERIALIZE the committed graph under --locked inside the pinned image. The committed lock is
#     mounted READ-ONLY, so Cargo physically cannot rewrite the authority, and --locked makes Cargo
#     ERROR (rather than silently updating) if the lock would need to change — a moving-registry
#     reselection is refused, not applied. Network is permitted ONLY to fetch the EXACT locked crate
#     bytes: versions + checksums come from Cargo.lock, no newer version can be chosen, and every
#     downloaded crate is inventoried into the vendor identity below. (`--offline` is used only where
#     a complete pre-populated cache is provisioned; otherwise the online fetch retrieves solely the
#     locked bytes.)
# ---- Third-party NOTICE packaging depends on this exact vendored graph.
vendor_tar="$out/$schema_cand.vendor.tar"
vendor_dir="$out/$schema_cand.vendor"
vendor_graph_in_container "$BUILDER_IMAGE_REF" "$cand_dir" "$dest" "$incontainer_lock" "$vendor_tar" \
  || die "in-container 'cargo vendor --locked' failed for $candidate (the committed graph did not materialize under LOCKED semantics; a lock/registry disagreement is a defect, never a silent reselection)"
rm -rf "$vendor_dir"
# Pre-enumerated safe extraction (reject absolute/traversal/link/device/duplicate BEFORE writing).
safe_extract_tar "$vendor_tar" "$vendor_dir"
# The exact downloaded per-file content identity of the vendored inputs — a substituted or altered
# vendored byte changes this hash, so a tampered vendor tree is caught.
vendor_inputs_hex="$(vendor_inputs_identity "$vendor_dir")"
is_bare_sha256 "$vendor_inputs_hex" || die "vendor-inputs identity malformed for $candidate: '$vendor_inputs_hex'"

# The owner-ratified per-family upstream notice map: supplies the real license text for crates that
# declare an SPDX license but ship no license file (fail closed on any no-file crate it does NOT
# cover). Committed next to the Stage-2 advisory-exception policy.
notice_map="$ROOT/policy/third-party-notice-map.json"
[ -f "$notice_map" ] || die "ratified third-party notice map absent: $notice_map"
closure_file="$out/$schema_cand.target-closure.json"
meta_dir="$out/$schema_cand.metadata"; rm -rf "$meta_dir"; mkdir -p "$meta_dir"
for t in $venue_targets; do
  cargo_metadata_target_in_container "$BUILDER_IMAGE_REF" "$cand_dir" "$dest" "$incontainer_lock" "$t" > "$meta_dir/$t.json" \
    || die "in-container 'cargo metadata --locked --filter-platform $t' failed for $candidate (cannot build closure)"
  [ -s "$meta_dir/$t.json" ] || die "empty cargo metadata for $candidate/$t"
done
# Build the sealed closure: nodes = ALL lock packages (so the closure cannot omit a locked crate);
# normal edges unioned over the target metadata; bound to (candidate, arch, targets, lock hash). The
# stage2_graph binding is the same candidate lock hash the Stage-2 audit is bound to.
python3 - "$closure_file" "$dest" "$schema_cand" "$arch" "$lock_hex" "$meta_dir" $venue_targets <<'PY'
import json, sys, os
out, lockfile, cand, arch, lockhash, meta_dir = sys.argv[1:7]
targets = sys.argv[7:]
US = "\x1f"
def pkgid(n, v, s): return f"{n}{US}{v}{US}{s}"
# all lock packages (nodes must equal the lock set)
pkgs, cur = [], None
for line in open(lockfile):
    t = line.strip()
    if t == "[[package]]":
        if cur: pkgs.append(cur)
        cur = {}
    elif cur is not None:
        if t.startswith("name = "): cur["name"] = t.split('"')[1]
        elif t.startswith("version = "): cur["version"] = t.split('"')[1]
        elif t.startswith("source = "): cur["source"] = t.split('"')[1]
        elif t.startswith("checksum = "): cur["checksum"] = t.split('"')[1]
if cur: pkgs.append(cur)
node_ids = {pkgid(p["name"], p["version"], p.get("source", "")) for p in pkgs}
edges, roots = {}, set()
for tgt in targets:
    m = json.load(open(f"{meta_dir}/{tgt}.json"))
    id2 = {p["id"]: pkgid(p["name"], p["version"], p.get("source") or "") for p in m["packages"]}
    for r in m["workspace_members"]:
        if r in id2: roots.add(id2[r])
    for node in m["resolve"]["nodes"]:
        nid = id2.get(node["id"])
        if not nid: continue
        e = edges.setdefault(nid, set())
        for dep in node.get("deps", []):
            if any(dk.get("kind") is None for dk in dep.get("dep_kinds", [])):
                dp = id2.get(dep["pkg"])
                if dp: e.add(dp)
nodes = []
for p in sorted(pkgs, key=lambda x: (x["name"], x["version"], x.get("source", ""))):
    pid = pkgid(p["name"], p["version"], p.get("source", ""))
    nd = sorted(d for d in edges.get(pid, set()) if d in node_ids)
    node = {"name": p["name"], "version": p["version"], "source": p.get("source", ""), "normal_deps": nd}
    if p.get("checksum"): node["checksum"] = p["checksum"]
    nodes.append(node)
closure = {"schema_version": 1, "candidate": cand, "arch": arch, "venue_targets": targets,
           "features": [], "lock_blake3_hex": lockhash, "stage2_graph_blake3_hex": lockhash,
           "roots": sorted(r for r in roots if r in node_ids), "nodes": nodes}
json.dump(closure, open(out, "w"), indent=1)
PY
[ -s "$closure_file" ] || die "failed to build target-closure for $candidate"
# The materialized-closure identity: the domain-free BLAKE3 of the sealed target-closure record
# produced under --locked (nodes = the exact locked package set).
closure_hex="$(blake3_hex_file "$closure_file")"
is_bare_sha256 "$closure_hex" || die "materialized-closure identity malformed for $candidate: '$closure_hex'"

# (5) POST-materialization byte-equality: no Cargo command rewrote the authority. Both the exported
#     copy AND the committed source-of-truth lock on disk must still be byte-identical to the pre-run
#     bytes.
post_sha256="$(sha256_hex_stdin < "$dest")"
[ "$post_sha256" = "$pre_sha256" ] \
  || die "exported lock was MUTATED during materialization: post $post_sha256 != pre $pre_sha256 (a Cargo command rewrote it; refusing)"
cmp -s "$committed_lock" "$dest" \
  || die "committed source-of-truth lock diverged from the exported lock after materialization; refusing"
committed_post_sha256="$(sha256_hex_stdin < "$committed_lock")"
[ "$committed_post_sha256" = "$pre_sha256" ] \
  || die "committed source-of-truth lock was mutated on disk during materialization: $committed_post_sha256 != $pre_sha256; refusing"

# (6) Record the COMMITTED-SOURCE-OF-TRUTH provenance: origin, builder + clean-commit binding, the
#     committed SHA-256 + domain-separated BLAKE3, the POST-run sha256 (pre/post byte equality), the
#     locked-command log, and the materialized-closure + vendored-input identities. Nothing here
#     claims the lock was freshly generated: it was copied from the committed source of truth and
#     materialized under --locked.
prov="$out/$schema_cand.lock-provenance.json"
python3 - "$prov" "$schema_cand" "$arch" "$BUILDER_IMAGE_DIGEST" "$source_commit" \
  "$pre_sha256" "$lock_hex" "$post_sha256" "$cmdlog_hex" "$closure_hex" "$vendor_inputs_hex" <<'PY'
import json, sys
(path, cand, arch, digest, commit, pre_sha, lock_b3, post_sha,
 cmdlog, closure, vendor) = sys.argv[1:12]
with open(path, "w") as f:
    json.dump({
        "candidate": cand,
        "arch": arch,
        "origin": "committed-source-of-truth",
        "container_digest": digest,
        "source_commit": commit,
        "committed_lock_sha256_hex": pre_sha,
        "committed_lock_blake3_hex": lock_b3,
        "post_lock_sha256_hex": post_sha,
        "locked_command_log_blake3_hex": cmdlog,
        "materialized_closure_blake3_hex": closure,
        "vendor_inputs_blake3_hex": vendor,
    }, f, indent=2)
    f.write("\n")
PY

# Independently re-verify (the resolver's recorded values are not trusted): reject a wrong origin, a
# mutated lock, or a hash that does not recompute from the committed bytes.
cargo run --quiet --locked --manifest-path "$VAL" --bin venue-verify -- \
  verify-lock "$prov" "$committed_lock" \
  || die "committed-source-of-truth lock provenance verification failed (wrong origin, hash-vs-bytes mismatch, mutated lock, or missing binding)"

note "materialized committed $dest + provenance $prov"

# NON-GATING TEST_ONLY drift diagnostic (off by default). When explicitly requested, run an
# UNCONSTRAINED `cargo generate-lockfile` in a THROWAWAY container and REPORT whether it would drift
# from the committed authority. It is diagnostic ONLY: it never rewrites the committed lock, never
# feeds the provenance, and NEVER fails the run — a drift is EXPECTED whenever the registry has
# published a newer semver-compatible release (exactly why the venue materializes the committed lock
# under --locked instead of regenerating).
if [ "${B0PRE_TESTONLY_LOCK_DRIFT_DIAG:-0}" = "1" ]; then
  drift_lock="$out/$schema_cand.TESTONLY-unconstrained.Cargo.lock"
  if gen_lock_in_container "$BUILDER_IMAGE_REF" "$cand_dir" "$drift_lock" 2>/dev/null; then
    if cmp -s "$drift_lock" "$committed_lock"; then
      note "TEST_ONLY drift diagnostic (NON-GATING): an unconstrained resolve MATCHES the committed lock (no drift)"
    else
      note "TEST_ONLY drift diagnostic (NON-GATING): an unconstrained 'cargo generate-lockfile' DRIFTS from the committed authority; the venue correctly ignores it and materializes the committed lock under --locked"
    fi
  else
    note "TEST_ONLY drift diagnostic (NON-GATING): the unconstrained resolve did not complete"
  fi
  rm -f "$drift_lock"
fi

# ---- Third-party NOTICE manifest: generate the per-candidate notice set from the crates' OWN
# license files in the materialized vendor tree, bound to THIS candidate's verified committed lock
# hash ($lock_hex). Fails closed on any registry crate whose notice is uncollectable. import-bundle
# re-verifies completeness + binding independently.
cargo run --quiet --locked --manifest-path "$VAL" --bin venue-verify -- \
  notices-generate "$schema_cand" "$arch" "$lock_hex" "$dest" "$vendor_dir" \
  "$out/$schema_cand.third-party-notices.json" "$notice_map" "$closure_file" \
  || die "third-party notices-generate failed for $candidate (uncollectable + unmapped => fail closed)"
# Independent cross-verify: completeness + lock/map binding, and the fail-closed classification check
# against the recomputed closure (exactly what import-bundle enforces).
cargo run --quiet --locked --manifest-path "$VAL" --bin venue-verify -- \
  notices-verify "$lock_hex" "$dest" "$out/$schema_cand.third-party-notices.json" "$notice_map" \
  || die "third-party notices-verify failed for $candidate (incomplete/mis-bound/unratified notice set)"
cargo run --quiet --locked --manifest-path "$VAL" --bin venue-verify -- \
  notices-verify-classification "$out/$schema_cand.third-party-notices.json" "$closure_file" "$dest" "$lock_hex" "$lock_hex" \
  || die "third-party notices classification does not match the recomputed target closure for $candidate"
rm -rf "$meta_dir"
rm -f "$vendor_tar"; rm -rf "$vendor_dir"   # transport artifacts; the manifest carries the texts
rm -f "$locked_cmd"                          # transport; provenance carries locked_command_log_blake3_hex
note "recorded $out/$schema_cand.third-party-notices.json + $schema_cand.target-closure.json (lock-bound, target-scoped)"
