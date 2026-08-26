# B0-FINAL official measurement runbook (x86_64 measurement; x86_64 + aarch64 identity)

Produces the official R0 measurement grid bound to the merged, finalized
`b0_pre_spec_hash = e933e7325c2639a48d8e25f20746d0f8abc822dee9fcfa87c2e6cdec226cf2a2`.

**Reviewed two-cell measurement model.** Terminal native measurement is eligible on **x86_64 only**,
for **both** candidates: the two measurement cells are **SP1/x86_64** and **RISC0/x86_64**. SP1/aarch64
terminal Groth16 (no first-party linux/arm64 gnark backend) and RISC0/aarch64 are **ratified-UNSUPPORTED**
and are **never measured** — `measure_fragment.sh` refuses them before any proving. The **identity** set
stays **three** records (SP1/x86_64, SP1/aarch64, RISC0/x86_64): the SP1 guest is *built* for aarch64 as
an identity in the shared guest set, but that identity is NEVER a measurement or proof. The eligibility/
unsupported model is carried as a retained, content-addressed `EligibilityMatrixV1` record, bound by
address into the `MeasurementInputAuthorityV1` and re-decoded + recomputed by both verifiers. The prior
`201cfcb8…` spec and any package/MIA/records/fragments bound to it are **superseded** — every production
path refuses the old spec after this migration.

The measurement producer is **checked-in Rust**, not shell scaffolding:

| Component | Crate / path | Role |
|---|---|---|
| Measurement core | `tools/b0-pre-measure-core` | backend trait (sole crypto boundary), identity binding, RSS capture, RawFacts emission, fail-closed orchestration — unit-tested off-venue |
| SP1 runner | `tools/b0-pre-measure-sp1` | real SP1 6.3.1 Groth16 backend (`--features real-backend`) |
| RISC Zero runner | `tools/b0-pre-measure-risc0` | real RISC Zero 3.0.5 backend + `embed_methods` guest build (`--features real-backend`) |
| Provenance reader | `tools/b0-pre-host-provenance` | reads the real host/cgroup facts |
| Verifier material | `tools/b0-pre-candidates/harness/{sp1,risc0}-verifier-material` | pinned VMAT manifest JSON |
| Orchestrator | `tools/b0-pre-candidates/scripts/measure_fragment.sh` | thin driver over the real binaries (no mocks, no fail-open) |

Nothing here changes the frozen protocol, spec hash, workload, thresholds, candidate SDK
pins, or guest logic, and **no candidate is selected** (that is B0-FINAL aggregation).

## 0. Preconditions (both hosts)

1. **Turbo already disabled** (the provenance reader REFUSES a turbo-enabled or
   indeterminate host; it never changes host settings):
   - Intel: `echo 1 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo`
   - governor `performance` on every CPU.
2. **A delegated, resettable proving cgroup.** cgroup v2 with a kernel that supports
   `memory.peak` reset-on-write (≥ 6.x), delegated to the operator so the firewall can place
   the prove container in it and read its per-cell peak:
   ```
   sudo mkdir -p /sys/fs/cgroup/b0-final-proving.slice
   sudo chown -R "$USER" /sys/fs/cgroup/b0-final-proving.slice        # delegate
   # PROVING_CGROUP is the path RELATIVE to /sys/fs/cgroup:
   export PROVING_CGROUP=b0-final-proving.slice
   ```
3. **Clean, fresh `OUT`** per run. **Native host, no emulation.**
4. **Provisioned venue**: pinned prover toolchains + `docker_firewall.sh`, per `VENUE.md`.
5. **Ratified toolchain-authority record.** The expected per-(candidate,arch) toolchain
   identity is sourced ONLY from `docs/b0-pre/venue/toolchain-authority.v1.json` (default;
   override with `TOOLCHAIN_AUTHORITY_RECORD`), whose BLAKE3 is verified against
   `B0_RATIFIED_TOOLCHAIN_AUTHORITY_B3` in `scripts/lib.sh` before any value is sourced — never
   an operator env var. Its committed values are a **fail-closed template**; the owner ratifies
   the real values (replacing the entries AND the `lib.sh` constant in one reviewed commit)
   before measurement, or every build's toolchain check refuses.
6. **Explicit, verified Cargo (never rely on login PATH).** A fresh, non-login venue shell may
   not have `cargo` on `PATH` (rustup exports it from the login profile). Pin an explicit,
   verified path once and invoke `"$CARGO"` for every build/run/test below — never a bare
   `cargo`:
   ```
   export CARGO="${CARGO:-$HOME/.cargo/bin/cargo}"
   [ -x "$CARGO" ] || { echo "REFUSED: verified cargo not executable at $CARGO" >&2; exit 1; }
   "$CARGO" --version
   ```

## 1. Build the real binaries (once per host)

```
# SP1 runner (native SP1 6.3.1 SDK):
"$CARGO" build --release --features real-backend --manifest-path tools/b0-pre-measure-sp1/Cargo.toml

# RISC Zero runner (x86_64 host only): embed_methods builds the frozen guest with the pinned
# LOCAL r0 toolchain — B0_VENUE_EMBED=1 + the isolated RISC0_HOME turn the real build on.
B0_VENUE_EMBED=1 RISC0_HOME="$PROVER_RISC0_HOME" \
  "$CARGO" build --release --features real-backend --manifest-path tools/b0-pre-measure-risc0/Cargo.toml

# provenance reader + verifier-material harnesses:
"$CARGO" build --release --manifest-path tools/b0-pre-host-provenance/Cargo.toml
"$CARGO" build --release --manifest-path tools/b0-pre-candidates/harness/sp1-verifier-material/Cargo.toml
"$CARGO" build --release --manifest-path tools/b0-pre-candidates/harness/risc0-verifier-material/Cargo.toml
```

The runners **refuse to build** without `--features real-backend` (there is no mock or
fallback proving path in a production binary); the RISC Zero runner without `B0_VENUE_EMBED`
compiles with an empty embedded ELF and **refuses at runtime** (never a stub proof).

## 2. Phase 1 — derive the guest-set hash (never operator-supplied)

The canonical `r0_guest_set_hash` binds EVERY measurement cell, so it is derived AFTER all
eligible guests are built and reconciled — not handed in by an operator.

**On each host, emit the reproducible identity record** (builds the guest TWICE and requires a
byte-identical typed record — no proof, no measurement):
Phase 1 builds all **three** guest identities (SP1/x86_64, SP1/aarch64, RISC0/x86_64). SP1/aarch64 is an
**identity-only** guest build — it enters the shared guest set (its arch-independent program_id reconciles
across both SP1 builders) but is NEVER measured. This step emits reproducible identity records; it runs no
proof and no measurement.

```
# x86_64 venue:
SPEC_HASH=e933e732…f2a2  REPO_DIR="$PWD"  PROVER_REAL_DOCKER=/usr/bin/docker \
  MEASURE_RUNNER=target/release/b0-pre-measure-sp1  VMAT_BIN=target/release/sp1-verifier-material \
  PROV_BIN=target/release/b0-pre-host-provenance  VERIFIER_REF=<pinned sp1 builder> \
  bash tools/b0-pre-candidates/scripts/derive_guest_set.sh emit sp1   x86_64 records/sp1-x86_64.json
SPEC_HASH=…  REPO_DIR="$PWD"  MEASURE_RUNNER=target/release/b0-pre-measure-risc0 \
  VMAT_BIN=target/release/risc0-verifier-material  PROV_BIN=… \
  bash tools/b0-pre-candidates/scripts/derive_guest_set.sh emit risc0 x86_64 records/risc0-x86_64.json

# aarch64 venue (SP1 IDENTITY only — builds the guest, emits the identity record; NO measurement):
… MEASURE_RUNNER=target/release/b0-pre-measure-sp1  VERIFIER_REF=<pinned sp1 builder, aarch64> \
  bash tools/b0-pre-candidates/scripts/derive_guest_set.sh emit sp1 aarch64 records/sp1-aarch64.json
```

**Transfer + verify between venues.** Copy the three record JSONs to a coordinator; verify each
transfer by BLAKE3 (`b3sum records/*.json`) against the value recorded at the producing venue —
a record whose hash does not match is rejected, never assembled. Then assemble:
```
SPEC_HASH=…  MEASURE_PRODUCE=tools/b0-pre-validator/target/release/measure-produce \
  bash tools/b0-pre-candidates/scripts/derive_guest_set.sh assemble records/ set/
```
`measure-produce --guest-set` requires EXACTLY (Sp1,x86_64)+(Sp1,aarch64)+(Risc0,x86_64),
rejects duplicates / missing / RISC-Zero-aarch64 / dirty / mock-stub / mismatched commit+spec,
reconciles SP1 across arches (program/vkey identity must agree; both builder records kept),
computes `r0_guest_set_hash` through the existing library code, and writes
`set/{guest-allowlist.bin, r0_guest_set_hash.txt, coordination-manifest.json}`. Distribute
`set/coordination-manifest.json` + `records/` to both measurement venues; each independently
**re-derives + verifies the manifest content hash** before proving (below).

## 3. Per-host measurement run

Set the shared env, then invoke the orchestrator once per (candidate, arch). Every value is
real: guest identities come from the built guest/SDK, verifier material from the harness,
provenance from the host, proving RSS from the prove container's **fresh per-cell cgroup**,
verify RSS from `getrusage`. The build-provenance identities (source-tree, dep-lock,
build-command, container/builder digests) are **derived by the orchestrator** from the actual
checkout / lock / build command / reconciled image — they are NOT accepted from the caller.

### 3.0 Generate the measurement-input authority (deterministic, pre-grid)

Before any proving cell, generate the ONE sealed `MeasurementInputAuthorityV1` package from the clean
two-root checkout. This is fully deterministic — the same clean measured-source + tooling roots reproduce
byte-identical members and addresses — and REPLACES the three former caller-supplied hashes with retained,
recomputable artifacts:

```
export MALFORMED_CORPUS_BIN=tools/b0-pre-malformed-corpus/target/release/b0-pre-malformed-corpus
bash tools/b0-pre-candidates/scripts/produce_measurement_input_authority.sh produce \
  "$B0_MEASURED_SOURCE_ROOT" "$B0_TOOLING_ROOT" "$OFFICIAL_JSON" "$B0_MEASUREMENT_AUTHORITY_PKG"
# Independent verification of the sealed package (decode + cross-bind + tooling==RATIFIED):
bash tools/b0-pre-candidates/scripts/produce_measurement_input_authority.sh verify \
  "$B0_MEASUREMENT_AUTHORITY_PKG"
```

The package holds `measurement-input-authority.v1.json` (the unifier: spec/workload + measured/tooling
identity + the harness-source inventory address + the malformed-corpus report address + the RSS
statement-binding policy + the **eligibility-matrix address**), plus the retained
`malformed-corpus-report.v1.json` (the fixed ordered corpus run through the real guest boundary, retaining
each member's exact bytes + stable refusal class), `harness-source-inventory.txt` (the canonical causal
source-closure manifest), and `eligibility-matrix.v1.json` (the retained `EligibilityMatrixV1`: the FROZEN
two-cell model — 3 identity cells, 2 native-measurement cells, exact unsupported set — self-addressed by
SHA-256 over its frozen preimage). `measure_fragment.sh` re-runs the **fail-fast gate**
(`measure-produce --verify-authority`, which now also decodes + recomputes the eligibility record and
requires the authority to bind exactly its address) before proving each fragment — it refuses a stale
package whose tooling commit/path-set ≠ the ratified measurement tooling — and embeds **all four** members
byte-identical into every fragment, so `--merge-fragments` refuses any byte or address disagreement across
fragments. All four members are MANDATORY; a package or fragment missing any of them is refused.

```
export SPEC_HASH=e933e7325c2639a48d8e25f20746d0f8abc822dee9fcfa87c2e6cdec226cf2a2
export GUEST_SET_MANIFEST=set/coordination-manifest.json  # phase-1 output (transfer-verified)
export IDENTITY_RECORDS=records/all.json                  # the 3 identity records (JSON array)
export MEASURE_PRODUCE=tools/b0-pre-validator/target/release/measure-produce
export REPO_DIR="$PWD"
export OFFICIAL_JSON=docs/b0-pre/fixtures/workload/official.json
export PROVER_FIREWALL_SH=tools/b0-pre-candidates/scripts/docker_firewall.sh
export PROVER_REAL_DOCKER=/usr/bin/docker                # ABSOLUTE, pre-verified docker
export PROVING_CGROUP=b0-final-proving.slice             # delegated, resettable (see §0.2)
export VMAT_BIN=target/release/sp1-verifier-material     # risc0-verifier-material for RISC0
export PROV_BIN=target/release/b0-pre-host-provenance
# The ONE sealed measurement-input authority package (generated deterministically in §3.0 below).
# There are NO caller-supplied RSS_CONTEXT_HASH / MALFORMED_CORPUS_RESULT_HASH / HARNESS_SOURCE_HASH:
# RSS context is bound per-cell, the malformed-corpus result is the retained report's own address, and
# the harness-source hash is the provenance-computed inventory digest — all three are DERIVED and sealed
# in this package, and a facts JSON carrying any of the three legacy variables is REFUSED.
export B0_MEASUREMENT_AUTHORITY_PKG="$OUT/measurement-input-authority"

# x86_64 venue — SP1 then RISC Zero:
MEASURE_RUNNER=target/release/b0-pre-measure-sp1 VERIFIER_REF=<pinned sp1 builder image> \
  PROVER_SP1_CONTENT_STORE=<digest store> \
  bash tools/b0-pre-candidates/scripts/measure_fragment.sh sp1   x86_64 "$OUT"
MEASURE_RUNNER=target/release/b0-pre-measure-risc0 VMAT_BIN=target/release/risc0-verifier-material \
  PROVER_R0VM_DIR=<pinned r0vm dir> PROVER_RISC0_HOME="$PROVER_RISC0_HOME" \
  bash tools/b0-pre-candidates/scripts/measure_fragment.sh risc0 x86_64 "$OUT"

# NO aarch64 MEASUREMENT. SP1/aarch64 terminal Groth16 and RISC0/aarch64 are ratified-UNSUPPORTED:
# measure_fragment.sh refuses them BEFORE any proving (native-ineligible; never emulated / QEMU / network
# prover / native-gnark / fabricated). The SP1/aarch64 identity lives only in the Phase-1 guest set above.
# The two measurement cells are exactly SP1/x86_64 and RISC0/x86_64.
```

Each invocation writes `"$OUT"/facts-<candidate>-<arch>.json` (a **RawFacts fragment**: 2
statements × **1 architecture (x86_64)** × 10 iterations = **20 measured proofs**, **100 verification
samples per proof**, real timings, proof bytes/hash, container-cgroup proving RSS, native verify RSS, host
provenance — every measured cell is x86_64; no aarch64 cell may exist), a runner
attestation `attestation-<candidate>-<arch>.json` (binds the **production binary BLAKE3** +
**enabled backend identity**, `real_backend: true`), and the firewall execution attestation.

## 3. Validate fragments early

```
"$CARGO" run --release --manifest-path tools/b0-pre-validator/Cargo.toml --bin measure-produce -- \
  --validate <merged-raw-facts.json>
```

## 4. Coordinate + assemble the official package

Do NOT hand-merge JSON. Merge **exactly the two** measurement fragments with the typed producer step
(requires EXACTLY {SP1/x86_64, RISC0/x86_64}; rejects duplicate/missing/extra fragments and refuses an
SP1/aarch64 or RISC0/aarch64 measurement fragment as ratified-unsupported; verifies source/spec agreement
+ byte-identical measurement-input authority incl. the eligibility record across both fragments):

```
MP=tools/b0-pre-validator/target/release/measure-produce
$MP --merge-fragments "$OUT/merged" \
  "$OUT"/facts-sp1-x86_64.json "$OUT"/facts-risc0-x86_64.json
```

Produce the package, BOUND to the phase-1 guest set. The identity RECORDS are a required
input: the guest set is INDEPENDENTLY RE-DERIVED from them (never trusting a manifest field),
the coordination manifest (optional 4th arg) is authenticated against that re-derivation, and
production refuses if the package's `r0_guest_set_hash` ≠ the re-derived value:

```
$MP --facts "$OUT/merged/merged-raw-facts.json" "$OUT/package" \
    records/all.json  set/coordination-manifest.json
#  -> real-orchestrator-vector.bin, inventory.json, package-id.txt
```

Independently re-verify the ACTUAL produced package (not just the committed fixture) with the
from-scratch verifier, and confirm its derived verdicts:

```
"$CARGO" run --release --manifest-path tools/b0-pre-independent/Cargo.toml \
  --bin b0-pre-independent-verify -- "$OUT/package/real-orchestrator-vector.bin"
#  -> {"r0_guest_set_hash":"…","candidates":[{"candidate":1,"verdict":"qualified"},
#                                            {"candidate":2,"verdict":"qualified"}]}
# Two-cell model: BOTH SP1/x86_64 and RISC0/x86_64 carry their COMPLETE x86_64-only native matrix (20
# proofs) and both verify + qualify. Neither is an "incomplete native matrix" — x86_64 IS the complete
# native matrix. Aggregation/selection use ONLY these two eligible measurement cells and never imply ARM
# performance was measured. Selecting the B0-FINAL candidate is B0-FINAL aggregation, not this runbook.
```

The committed-fixture agreement tests remain a separate regression gate:
```
"$CARGO" test --manifest-path tools/b0-pre-validator/Cargo.toml  --test producer_vector
"$CARGO" test --manifest-path tools/b0-pre-independent/Cargo.toml --test producer_vector
```

## 5. Preservation / archive

Preserve the whole `$OUT` (fragments, runner + firewall attestations, merged RawFacts,
`package/`) read-only; record `package-id.txt` (= `blake3(real-orchestrator-vector.bin)`);
deallocate the VMs only after the package is mirrored and independently re-verified.

## Non-negotiables

- **Two-cell model.** Measure ONLY SP1/x86_64 and RISC0/x86_64. Never fabricate, emulate, QEMU, network-
  prove, native-gnark, or otherwise synthesize an SP1/aarch64 or RISC0/aarch64 measurement or proof — both
  are ratified-UNSUPPORTED and refused before proving. Never imply ARM performance was measured.
- **Three identities, two measurements.** The guest set retains three identity records (SP1/x86_64,
  SP1/aarch64, RISC0/x86_64); exactly two of them are measurement cells. The SP1/aarch64 identity is never
  a measurement. The retained eligibility record + its MIA binding are MANDATORY; a package/fragment
  missing the eligibility record, or whose eligibility model disagrees with the enforced native
  eligibility, is refused.
- **Superseded spec.** The finalized `b0_pre_spec_hash` is `e933e732…f2a2`. The prior `201cfcb8…` spec and
  any MIA / records / identities / fragments / packages bound to it are superseded and refused — never mix
  old and new.
- Never edit the finalized spec hash / protocol / thresholds / guest logic outside a reviewed authority
  cycle.
- The `measure-produce --dry-run` package is TEST-ONLY synthetic scaffolding and must never
  be presented as measurement evidence.
