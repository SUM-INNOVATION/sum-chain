#!/usr/bin/env bash
# Produce the in-container-generated candidate Cargo.lock for one candidate, copied
# out to the workdir as the Stage-6 lock input (<Candidate>.Cargo.lock), together
# with its generated-in-container PROVENANCE. The lock is the full transitive source
# of truth resolved by `cargo generate-lockfile` INSIDE the pinned builder image;
# the host never supplies it.
#
# Blocker 2 (host-lock rejection): the authoritative path REFUSES any host-supplied
# lock. The former SP1_CONTAINER_LOCK / RISC0_CONTAINER_LOCK host-path acceptance is
# GONE — setting either is an error. The lock is generated in-container, exported,
# bound to (candidate, arch, container_digest, source_commit, command_log), and its
# hash is recomputed from the EXPORTED bytes and independently re-verified by
# `venue-verify verify-lock` (which recomputes it again and rejects a host origin or
# any mismatch). Off-venue (no Docker/builder image) this fails closed.
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

# AUTHORITATIVE: the lock is GENERATED in-container; a host-supplied lock is refused.
[ -z "${SP1_CONTAINER_LOCK:-}${RISC0_CONTAINER_LOCK:-}" ] \
  || die "host-supplied lock env (SP1_CONTAINER_LOCK/RISC0_CONTAINER_LOCK) is refused; the lock must be generated in-container"
require_linux_oci_builder
require_cmd b3sum
require_cmd python3
[ -n "${BUILDER_IMAGE_REF:-}" ] || nyr "BUILDER_IMAGE_REF (the pinned builder image the lock is generated inside) is required"
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

# Generate the lock INSIDE the pinned builder image (no network beyond the pinned
# registry the image is configured for) and export the resulting bytes + the exact
# command log. The host filesystem contributes no lock. The builder image bakes in the
# CURATED staged guest graph (candidate workspace + guest-core + sumchain-wire + curated
# workspace root, at their reproduced repo-relative paths), so `cargo generate-lockfile`
# in the candidate workspace resolves the COMPLETE transitive graph — guest + guest-core
# + sumchain-wire + all their crates.io deps — into ONE lock, not just the candidate
# crate's direct pins. Before the container context staging existed, the guest path deps
# were absent and this resolution could not even complete.
#
# YANKED-VERSION NOTE (verified). The graph transitively pulls `lazy_static 1.5.0`,
# whose optional `spin_no_std` feature requires `spin = ^0.9.8`; `spin 0.9.8` is YANKED
# on crates.io. This does NOT block the fresh lock: `^0.9.8` is also satisfied by the
# NON-YANKED `spin 0.9.9`, and the v2 resolver refuses a yanked version for a fresh lock
# and selects `0.9.9`. A fresh `cargo generate-lockfile` over BOTH candidate graphs was
# confirmed to resolve `spin 0.9.9` from the authoritative registry (sp1: 532 pkgs,
# risc0: 359 pkgs). No host lock, un-yank, invented version, or vendored source is
# needed. Regression:
# tools/b0-pre-validator/tests/candidate_lock_yanked_spin.rs. (An `--offline` resolve on
# a dev host with only `spin-0.9.8.crate` cached fails spuriously — an offline-mode
# artifact, not a venue failure; the venue resolves online against the pinned registry.)
cand_dir="$(incontainer_candidate_dir "$candidate")"
gen_cmd="$out/$schema_cand.generate-lockfile.cmd"
gen_log="$out/$schema_cand.generate-lockfile.log"
printf 'docker run --rm --pull never %s bash -c "cd %s && cargo generate-lockfile" (candidate=%s; full staged path-dep graph)\n' \
  "$BUILDER_IMAGE_DIGEST" "$cand_dir" "$candidate" > "$gen_cmd"
# Shared production core (lib.sh): the real-container E2E drives the IDENTICAL generation.
gen_lock_in_container "$BUILDER_IMAGE_REF" "$cand_dir" "$dest" 2> "$gen_log" \
  || die "in-container 'cargo generate-lockfile' failed for $candidate (no host lock is substituted)"
[ -s "$dest" ] || die "in-container lock export for $candidate is empty; refusing"

# The COMMITTED candidate lock is the SOURCE OF TRUTH; the freshly generated in-container lock is
# an independent execution CHECK. Require EXACT byte equality (owner contract); the committed lock
# is authoritative and is NEVER regenerated or rewritten. (require_committed_lock above already
# refused a missing/symlink/empty committed lock; re-assert at compare time.)
committed_lock="$ROOT/candidates/$candidate/Cargo.lock"
{ [ -f "$committed_lock" ] && [ ! -L "$committed_lock" ] && [ -s "$committed_lock" ]; } \
  || die "committed source-of-truth lock missing/symlink/empty at compare time: $committed_lock"
cmp -s "$dest" "$committed_lock" \
  || die "in-container generated lock for $candidate is NOT byte-identical to the committed source-of-truth lock $committed_lock; refusing (the committed lock is authoritative and is never regenerated/rewritten)"

cmdlog_hex="$(blake3_hex_file "$gen_cmd")"
# Recompute the domain-separated lock hashes from the EXPORTED bytes (never a claim) — BOTH the
# generated lock and the committed source-of-truth lock — and require them equal (byte-identity,
# re-checked as defence in depth beyond the cmp above).
lock_hex="$(cargo run --quiet --locked --manifest-path "$VAL" --bin venue-verify -- lock-hash "$dest")" \
  || die "lock-hash recomputation failed for $dest"
committed_lock_hex="$(cargo run --quiet --locked --manifest-path "$VAL" --bin venue-verify -- lock-hash "$committed_lock")" \
  || die "committed lock-hash recomputation failed for $committed_lock"
[ "$lock_hex" = "$committed_lock_hex" ] \
  || die "generated lock hash ($lock_hex) != committed lock hash ($committed_lock_hex) for $candidate; refusing"

# Record the generated-in-container provenance bound to (candidate, arch,
# container_digest, source_commit, command_log, lock_hash).
prov="$out/$schema_cand.lock-provenance.json"
python3 - "$prov" "$schema_cand" "$arch" "$BUILDER_IMAGE_DIGEST" "$source_commit" "$cmdlog_hex" "$lock_hex" "$committed_lock_hex" <<'PY'
import json, sys
path, cand, arch, digest, commit, cmdlog, lockhash, committed_lockhash = sys.argv[1:9]
with open(path, "w") as f:
    json.dump({
        "candidate": cand,
        "arch": arch,
        "origin": "generated-in-container",
        "container_digest": digest,
        "source_commit": commit,
        "command_log_blake3_hex": cmdlog,
        "lock_blake3_hex": lockhash,
        "committed_lock_blake3_hex": committed_lockhash,
    }, f, indent=2)
    f.write("\n")
PY

# Independently re-verify: reject a host origin, recompute BOTH hashes from the exported (generated)
# bytes and the committed source-of-truth bytes, and require generated == committed (defence in
# depth — the resolver's recorded hashes are not trusted; the committed lock is never rewritten).
cargo run --quiet --locked --manifest-path "$VAL" --bin venue-verify -- \
  verify-lock "$prov" "$dest" "$committed_lock" \
  || die "lock provenance verification failed (host origin, hash mismatch, or generated!=committed)"

note "recorded in-container $dest + provenance $prov"

# ---- Third-party NOTICE packaging (compliance): vendor the EXACT locked graph inside the
# pinned builder image, then generate the per-candidate notice manifest from the crates' OWN
# license files. Bound to THIS candidate's verified lock hash ($lock_hex, recomputed from the
# exported bytes above) so the sealed bundle + import gate can require it byte-for-byte. Fails
# closed on any registry crate whose notice is uncollectable — a missing license is never a
# clean notice set. `import-bundle` re-verifies completeness + binding independently.
vendor_tar="$out/$schema_cand.vendor.tar"
vendor_dir="$out/$schema_cand.vendor"
incontainer_lock="$cand_dir/Cargo.lock"
vendor_graph_in_container "$BUILDER_IMAGE_REF" "$cand_dir" "$dest" "$incontainer_lock" "$vendor_tar" \
  || die "in-container 'cargo vendor' failed for $candidate (cannot collect third-party notices)"
rm -rf "$vendor_dir"
# Pre-enumerated safe extraction (reject absolute/traversal/link/device/duplicate BEFORE writing).
safe_extract_tar "$vendor_tar" "$vendor_dir"
# The owner-ratified per-family upstream notice map: supplies the real license text for crates that
# declare an SPDX license but ship no license file (fail closed on any no-file crate it does NOT
# cover). Committed next to the Stage-2 advisory-exception policy.
notice_map="$ROOT/policy/third-party-notice-map.json"
[ -f "$notice_map" ] || die "ratified third-party notice map absent: $notice_map"
# Target-scoping: seal the TARGET-CLOSURE record — the platform-resolved NORMAL-dependency graph for
# the venue build target(s) this candidate is actually built for. A crate not in the normal closure
# (a build-time-only or macOS/Windows-only dependency the artifact never ships) carries no notice.
# import-bundle independently RECOMPUTES the closure and requires the classification to match, so the
# not-redistributed marking is never trusted. SP1 builds x86_64 + aarch64 Linux; RISC Zero x86_64 only.
case "$candidate" in
  sp1)   venue_targets="x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu" ;;
  risc0) venue_targets="x86_64-unknown-linux-gnu" ;;
esac
closure_file="$out/$schema_cand.target-closure.json"
meta_dir="$out/$schema_cand.metadata"; rm -rf "$meta_dir"; mkdir -p "$meta_dir"
for t in $venue_targets; do
  cargo_metadata_target_in_container "$BUILDER_IMAGE_REF" "$cand_dir" "$dest" "$incontainer_lock" "$t" > "$meta_dir/$t.json" \
    || die "in-container 'cargo metadata --filter-platform $t' failed for $candidate (cannot build closure)"
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
note "recorded $out/$schema_cand.third-party-notices.json + $schema_cand.target-closure.json (lock-bound, target-scoped)"
