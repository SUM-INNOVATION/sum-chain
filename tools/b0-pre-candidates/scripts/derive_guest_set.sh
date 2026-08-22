#!/usr/bin/env bash
# B0-FINAL phase-1 guest-closure derivation (venue-only). Two modes:
#
#   derive_guest_set.sh emit    <sp1|risc0> <arch> <out_record.json>
#       Build the guest TWICE (clean) and extract its identity via the runner's
#       --emit-identity BOTH times; require the two typed identity records BYTE-IDENTICAL
#       (reproducibility), then write one record. NO proof, NO measurement.
#
#   derive_guest_set.sh assemble <records_dir> <out_dir>
#       Concatenate the collected per-(candidate,arch) records and run
#       `measure-produce --guest-set` to derive the canonical r0_guest_set_hash + the
#       content-addressed coordination manifest (fail-closed on the eligible-set rules).
#
# The coordinator collects the three records — (Sp1,x86_64) + (Sp1,aarch64) from the two
# SP1 venues, (Risc0,x86_64) from the x86 venue — then assembles. No operator-supplied hash.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
# shellcheck source=lib.sh
. "$HERE/lib.sh"
# Two-root authority resolver (measured source vs measurement tooling).
# shellcheck source=two_root_authority.sh
. "$HERE/two_root_authority.sh"

need_env() { [ -n "${!1:-}" ] || die "required env $1 is unset"; }
b3() { b3sum "$1" | awk '{print $1}'; }
b3_stdin() { b3sum | awk '{print $1}'; }

MODE="${1:-}"
case "$MODE" in
  emit)
    CAND="${2:-}"; ARCH="${3:-}"; OUT_REC="${4:-}"
    case "$CAND" in sp1|risc0) ;; *) die "candidate must be sp1|risc0" ;; esac
    case "$ARCH" in x86_64|aarch64) ;; *) die "arch must be x86_64|aarch64" ;; esac
    [ -n "$OUT_REC" ] || die "output record path required"
    [ "$CAND" = risc0 ] && [ "$ARCH" = aarch64 ] && die "RISC Zero aarch64 identity is native-ineligible; refused"
    require_native_arch "$ARCH"
    # TWO-ROOT authority: the FROZEN measured source and the REVIEWED tooling are SEPARATE clean
    # checkouts, supplied explicitly (never inferred). Guest/source identity derives ONLY from the
    # measured root; the runner/scripts are the tooling root; the tooling authority is bound
    # separately into the record. Refuses same/nested/dirty/wrong-commit roots + cross-root swaps.
    need_env B0_MEASURED_SOURCE_ROOT
    need_env B0_TOOLING_ROOT
    require_two_roots --measured-source-root "$B0_MEASURED_SOURCE_ROOT" --tooling-root "$B0_TOOLING_ROOT"
    for v in SPEC_HASH MEASURE_RUNNER VMAT_BIN PROV_BIN; do need_env "$v"; done
    # source_commit/clean-tree are read from the MEASURED root (never the tooling checkout HEAD).
    REPO_DIR="$B0_MEASURED_ROOT"
    [ "$CAND" = sp1 ] && need_env VERIFIER_REF
    [ "$CAND" = sp1 ] && need_env PROVER_REAL_DOCKER
    require_cmd b3sum; require_cmd python3
    [ -x "$MEASURE_RUNNER" ] && [ -x "$VMAT_BIN" ] && [ -x "$PROV_BIN" ] || die "runner/harness/prov bins must be executable"
    # #2: ratified expected toolchain identity, sourced from the hash-verified authority record.
    CANDCAP=Sp1; [ "$CAND" = risc0 ] && CANDCAP=Risc0
    : "${TOOLCHAIN_AUTHORITY_RECORD:=$ROOT/../../docs/b0-pre/venue/toolchain-authority.v1.json}"
    RATIFIED_TC="$(b0_ratified_toolchain_identity "$CANDCAP" "$ARCH" "$TOOLCHAIN_AUTHORITY_RECORD")" \
      || die "ratified toolchain authority record unavailable/invalid (hash-verify or entry lookup failed)"

    # Guest source + committed lock come ONLY from the MEASURED root (frozen source identity).
    GUEST_DIR="$B0_MEASURED_ROOT/candidates/$CAND/guest"; LOCK="$B0_MEASURED_ROOT/candidates/$CAND/Cargo.lock"
    [ -d "$GUEST_DIR" ] && [ -s "$LOCK" ] || die "candidate guest tree / lock absent in measured root"
    TREE_HASH="$(cd "$GUEST_DIR" && find . -type f -not -path './target/*' | LC_ALL=C sort | while IFS= read -r f; do b3 "$f"; done | b3_stdin)"
    LOCK_HASH="$(b3 "$LOCK")"
    # source commit + clean-tree from the tested provenance reader (git-backed), never assumed.
    PROVJSON="$("$PROV_BIN" "$ARCH" Proving --repo "$REPO_DIR" --builder-digest "$(printf '0%.0s' {1..64})" --tooling-root "$B0_TOOLING_ROOT")" \
      || die "provenance read (for source commit / clean tree) failed"
    SRC_COMMIT="$(printf '%s' "$PROVJSON" | grep -o '"source_commit": *"[0-9a-f]*"' | head -1 | grep -o '[0-9a-f]\{40\}')"
    DIRTY="$(printf '%s' "$PROVJSON" | grep -o '"dirty_tree_flag": *\(true\|false\)' | head -1 | grep -o 'true\|false')"
    [ -n "$SRC_COMMIT" ] || die "could not read source commit"
    CLEAN=true; [ "$DIRTY" = true ] && CLEAN=false
    VMAT_JSON="$(mktemp)"; "$VMAT_BIN" > "$VMAT_JSON" || die "verifier-material harness failed"

    scratch="$(mktemp -d)"; trap 'rm -rf "$scratch" "$VMAT_JSON"' EXIT
    RECIPE_HASH="$(b0_build_recipe_hash "$CAND")" || die "unknown build recipe for $CAND"
    emit_once() { # <n>
      local d="$scratch/b$1"; mkdir -p "$d/guest"
      # #2/#4: arch-neutral canonical recipe hash; #3: real toolchain identity (not a label).
      local -a idargs=(--emit-identity --arch "$ARCH" --spec-hash "$SPEC_HASH"
        --guest-source-tree-hash "$TREE_HASH" --candidate-dep-lock-hash "$LOCK_HASH"
        --build-command-hash "$RECIPE_HASH" --source-commit "$SRC_COMMIT" --clean-tree "$CLEAN"
        --verifier-material "$VMAT_JSON"
        # Two-root: bind the SEPARATE tooling authority into the identity record (never compared to
        # the measured source; verified against the tooling authority by the validator).
        --tooling-commit "$B0_TOOLING_COMMIT" --tooling-pathset-blake3 "$B0_TOOLING_PATHSET_BLAKE3")
      if [ "$CAND" = sp1 ]; then
        local rd; rd="$(readlink -f "$PROVER_REAL_DOCKER")"
        # CONSUME the ONE canonical SP1 guest artifact — NEVER rebuild. SP1's per-arch succinct
        # cross-compiler diverges across build hosts, so the grid's single-program requirement is met
        # by distributing the exact x86-authoritative ELF bytes to every arch. There is NO local
        # `cargo prove build` fallback for the official SP1 guest: a missing/invalid package refuses.
        need_env CANONICAL_SP1_GUEST_PKG
        [ -d "$CANONICAL_SP1_GUEST_PKG" ] || die "canonical SP1 guest package absent: $CANONICAL_SP1_GUEST_PKG"
        bash "$HERE/produce_canonical_sp1_guest.sh" verify "$CANONICAL_SP1_GUEST_PKG" >&2 \
          || die "canonical SP1 guest package failed independent verification; refusing"
        local canon_man="$CANONICAL_SP1_GUEST_PKG/canonical-sp1-guest-artifact.v1.json"
        local canon_elf="$CANONICAL_SP1_GUEST_PKG/guest.elf"
        [ -s "$canon_man" ] && [ -s "$canon_elf" ] || die "canonical SP1 guest package incomplete"
        # bind: the artifact must be the guest of THIS ratified measured source.
        local art_msc; art_msc="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["measured_source_commit"])' "$canon_man")"
        [ "$art_msc" = "$SRC_COMMIT" ] || die "canonical artifact measured_source_commit $art_msc != measured $SRC_COMMIT"
        local art_addr; art_addr="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["address"])' "$canon_man")"
        # use the retained ELF bytes verbatim; the runner derives program_id/guest_image_hash from
        # THESE bytes, so both arches necessarily agree (that is the shared-program guarantee).
        mkdir -p "$d/guest"; cp "$canon_elf" "$d/guest/guest.elf"
        # builder/toolchain identify THIS proving venue's ratified image (per-arch; reconcile_sp1 keeps
        # both). The shared guest identity is bound via --canonical-sp1-guest-artifact-address.
        local img; img="$("$rd" image inspect --format '{{.Id}}' "$VERIFIER_REF" 2>/dev/null || true)"
        case "$img" in sha256:*) ;; *) die "VERIFIER_REF did not reconcile to an immutable image id" ;; esac
        local tc; tc="$(b0_toolchain_identity sp1 "$img")"
        [ "$tc" = "$RATIFIED_TC" ] || die "SP1 toolchain identity $tc != ratified $RATIFIED_TC"
        idargs+=(--guest-elf "$d/guest/guest.elf" --builder-digest "${img#sha256:}" --toolchain-identity "$tc" \
                 --canonical-sp1-guest-artifact-address "$art_addr")
      else
        # #1: the RISC Zero guest is embedded at runner BUILD time, so a genuine second build
        # is a fresh `cargo build --features real-backend` with B0_VENUE_EMBED=1 into a SEPARATE
        # target dir; both independently-built runner binaries must agree on the identity.
        need_env RISC0_RUNNER_MANIFEST; need_env PROVER_RISC0_HOME
        local tgt="$d/target"
        ( cd "$ROOT/.." && B0_VENUE_EMBED=1 RISC0_HOME="$PROVER_RISC0_HOME" CARGO_TARGET_DIR="$tgt" \
            cargo build --release --features real-backend --manifest-path "$RISC0_RUNNER_MANIFEST" ) \
          || die "RISC Zero runner build $1 failed"
        local rbin="$tgt/release/b0-pre-measure-risc0"
        [ -x "$rbin" ] || die "RISC Zero runner binary $1 absent"
        local tc; tc="$(b0_toolchain_identity risc0 "$PROVER_RISC0_HOME")"
        [ "$tc" = "$RATIFIED_TC" ] || die "RISC0 toolchain identity $tc != ratified $RATIFIED_TC"
        idargs+=(--builder-digest "$(b3 "$rbin")" --toolchain-identity "$tc")
        # emit from THIS independently-built runner (not a single prebuilt one):
        "$rbin" "${idargs[@]}" > "$d/record.json" || die "runner --emit-identity $1 failed"
        return 0
      fi
      "$MEASURE_RUNNER" "${idargs[@]}" > "$d/record.json" || die "runner --emit-identity $1 failed"
    }
    emit_once 1; emit_once 2
    # Two clean builds MUST yield a byte-identical guest identity record.
    cmp -s "$scratch/b1/record.json" "$scratch/b2/record.json" \
      || die "guest identity is NOT reproducible: the two clean builds produced different records"
    cp "$scratch/b1/record.json" "$OUT_REC"
    note "emitted reproducible $CAND/$ARCH identity record -> $OUT_REC"
    ;;
  assemble)
    RECDIR="${2:-}"; OUTDIR="${3:-}"
    [ -d "$RECDIR" ] || die "records dir required"
    [ -n "$OUTDIR" ] || die "out dir required"
    for v in SPEC_HASH MEASURE_PRODUCE CANONICAL_SP1_GUEST_PKG; do need_env "$v"; done
    [ -x "$MEASURE_PRODUCE" ] || die "MEASURE_PRODUCE not executable"
    [ -d "$CANONICAL_SP1_GUEST_PKG" ] || die "canonical SP1 guest package absent: $CANONICAL_SP1_GUEST_PKG"
    recs="$(mktemp)"; trap 'rm -f "$recs"' EXIT
    # Concatenate the per-(candidate,arch) records into one JSON array.
    { printf '['; first=1; for f in "$RECDIR"/*.json; do [ -f "$f" ] || continue; [ "$first" = 1 ] || printf ','; cat "$f"; first=0; done; printf ']'; } > "$recs"
    # v8: measure-produce re-decodes the ONE canonical SP1 guest artifact from its retained bytes and
    # requires every SP1 record to reference exactly it; it is then sealed as a mandatory member.
    "$MEASURE_PRODUCE" --guest-set "$recs" "$OUTDIR" "$CANONICAL_SP1_GUEST_PKG" || die "guest-set assembly refused (eligible-set / reconciliation / canonical-artifact rule failed)"
    note "assembled guest set -> $OUTDIR (coordination-manifest.json, r0_guest_set_hash.txt, guest-allowlist.bin)"
    ;;
  *) die "usage: derive_guest_set.sh <emit <sp1|risc0> <arch> <out_record.json> | assemble <records_dir> <out_dir>>" ;;
esac
