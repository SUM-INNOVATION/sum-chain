# B0-PRE immutable venue-input pin proposal (DRAFT — not ratified)

Status: **DRAFT / NOT RATIFIED.** This document defines the *primary sources* and the
*automated verification* for every immutable venue input the authoritative run consumes.
It deliberately contains **no concrete pin values** — no digests, checksums, or URLs are
inserted here, and nothing in `VENUE.md` / the scripts is changed. Values are proposed,
verified against their primary source by `scripts/verify_pins.sh`, and only then submitted
for owner ratification in a separate step.

Pins are verified and ratified against the tree of the owner-ratified source commit
(`RATIFIED_SOURCE_COMMIT`; see RUNBOOK.md §1), not a hard-coded hash — so this proposal
does not go stale when the venue pipeline is corrected.

## Why pins, and the ratification rule

Every input below is an **immutable INPUT**, not a built artifact. The venue resolves it
by digest/checksum, never by mutable tag or "latest". A pin is eligible only when
`verify_pins.sh` re-derives it from the primary source and the derived value equals the
proposed value **exactly**; any mismatch fails closed. Ratification (inserting the values
into a ratified `pins.env` the runbook sources) is an owner decision made *after*
verification passes — never automatically.

## The pins, their primary sources, and verification method

| # | Pin | Primary source (authoritative) | How `verify_pins.sh` checks it |
|---|-----|-------------------------------|--------------------------------|
| 1 | `BASE_IMAGE` + `base_index_digest` + `BASE_DIGEST` (per-arch) | the base image's registry, resolved **by digest** | `docker manifest inspect "$BASE_IMAGE@$base_index_digest"` must resolve; its child manifests are **enumerated**, and each per-arch digest must be a child of that index declaring `linux/amd64` (x86_64) or `linux/arm64` (aarch64). Every digest must be a full `sha256:<64hex>` (never a tag). Metadata only — no image is pulled or executed, so the check holds on a host with QEMU/binfmt registered |
| 2 | `apt.debian_url` + `apt.debian_inrelease_sha256` + `apt.debian_security_url` + `apt.debian_security_inrelease_sha256` | the distro's immutable snapshot service (`snapshot.debian.org` / `snapshot.ubuntu.com`) | each base URL must be on an immutable snapshot service and end in `/`; the `InRelease` at `<url>dists/<suite>/InRelease` is fetched and its sha256 must equal the pinned value **exactly** |
| 3 | `rustup_init.version` + `rustup_init.<arch>` — per-arch `url` + `sha256` (ratified into `RUSTUP_INIT_URL` / `RUSTUP_INIT_SHA256`) | the official Rust release channel, **immutable archive** path `static.rust-lang.org/rustup/archive/<version>/<target>/rustup-init` | `version` must be the required rustup release; the URL must be the exact immutable archive locator for that version **and that architecture**; the unversioned `rustup/dist/` path is refused outright; then download and recompute `sha256` |
| 4 | SP1 tool identity — `sp1-verifier 6.3.1`, **one entry per architecture** | the pinned SP1 release artifact (its immutable download URL) | the initial URL must be an allow-listed **https** primary host and its effective (post-redirect) host must be an allow-listed delivery host, exact-matched; then download the declared `artifact_identity`, recompute the checksum, compare to `checksum_hex` |
| 5 | RISC Zero tool identities — `risc0-zkvm 3.0.5`, `risc0-groth16 3.0.4`, **x86_64 only** | the pinned RISC Zero release artifacts | same host/redirect/download/compare as (4). An `aarch64` RISC Zero entry is **refused**: Groth16 and verifier-material extraction are native-x86_64-only (VENUE.md §2) |
| 6 | `cargo_audit` — `version` + `crate_sha256` + `source_commit` + `packaged_lock_sha256` | the pinned crates.io release `cargo-audit-<version>.crate` at `static.crates.io` | `version` must be the required cargo-audit release; the `.crate` is downloaded from `static.crates.io` and its `sha256` must equal `crate_sha256`; the packaged `cargo-audit-<version>/Cargo.lock` is extracted from that **same verified tarball** and its `sha256` must equal `packaged_lock_sha256` (pinning the auditor's own dependency graph); `source_commit` is a 40-hex provenance field (the tag the release was cut from), format-checked here |
| 7 | `advisory_db` — `repo` + `commit` + `git_tree` + `content_blake3` | the canonical RustSec `advisory-db` GitHub repository | `repo` must be the canonical `https://github.com/rustsec/advisory-db`; the GitHub commits API resolves `commit` → its tree sha, which must equal `git_tree` (a swapped commit or fabricated tree fails without cloning history); `content_blake3` is the canonical checkout digest (domain-separated BLAKE3, `ADVDB_CHECKOUT_TAG`), format-checked here and **re-derived in full at produce time** by `venue-verify checkout-digest` over the READ-ONLY mounted checkout (and reproduced by an independent reference in the validator test suite) |
| 8 | `prover_archives` — per (archive, arch): `archive_url` + `archive_sha256`, and per **member**: `executable_name` + `member_path` + `member_sha256` + `member_size_bytes` + `version_argv` + `version_output` + `expected_release_commit` + `delivery` | the pinned SP1 / RISC Zero prover release **archives** and the exact executables inside them | `verify_pins.sh` validates the SHAPE + COVERAGE + shared-archive + delivery + no-`rzup` invariants (each `archive_sha256` / `member_sha256` a bare 64-hex; `member_size_bytes` a positive integer; `version_output` carries `expected_release_commit`; `delivery` is `isolated-path` for cargo subcommands and `risc0-server-path` for `r0vm`; `cargo-prove` present for **x86_64 AND aarch64**, `cargo-risczero` + `r0vm` **x86_64-only** and **sharing one archive**; a swapped-arch / wrong-member / wrong-size / altered-digest / incorrect-version / forbidden-`r0vm` value all fail closed). The **member bytes** are content-verified **in-image** by the staged provisioner (below), and the same values are golden-tested against the transferred content-addressed venue report |

Notes:
- The **base image** identity IS the pinned per-arch digest, and it must belong to the
  pinned immutable **index**; its provenance is the base-resolution command/output,
  distinct from the builder's two-build evidence (VENUE.md §3).
- The APT pin is **four exact fields**, not a bare timestamp. A timestamp alone could not
  be verified: `snapshot.debian.org` resolves *any* timestamp to the nearest **preceding**
  snapshot, so a nonexistent date still answered. The `InRelease` content hash is the
  snapshot's real identity, and both Dockerfiles re-check it **before apt installs
  anything**. Hash pinning **supplements** apt's OpenPGP verification; it never replaces it.
- Both Dockerfiles remove every pre-existing apt source before the first `apt-get update`
  and assert that no rolling `deb.debian.org` / `security.debian.org` source survives. The
  Debian base image ships a deb822 `sources.list.d/debian.sources` pointing at the rolling
  mirror, which previously stayed active alongside the snapshot.
- `RUSTUP_INIT_URL` + `RUSTUP_INIT_SHA256` gate that Rust **1.88.0** is installed *inside*
  the builder from an exact immutable artifact, never assumed present (VENUE.md §1).
- Tool identities are fail-closed and **per (candidate, architecture)**: a version string
  alone never preregisters the bytes; authoritative assembly refuses any absent, synthetic,
  cross-architecture, or swapped value (VENUE.md §3.5).

## Proposed-value file (operator fills; kept OUT of the repo until ratified)

`verify_pins.sh` reads a proposed-pins file of exactly this shape (this is the single
authoritative schema — the script is the contract, this document mirrors it). Values are
shown **empty**; a committed, byte-identical UNRATIFIED example lives at
`tools/b0-pre-candidates/scripts/tests/fixtures/proposed-pins.documented-shape.json`.

```json
{
  "base_image": "",
  "base_index_digest": "",
  "base_digest": { "x86_64": "", "aarch64": "" },
  "apt": {
    "debian_url": "",
    "debian_inrelease_sha256": "",
    "debian_security_url": "",
    "debian_security_inrelease_sha256": ""
  },
  "rustup_init": {
    "version": "1.29.0",
    "x86_64": { "url": "", "sha256": "" },
    "aarch64": { "url": "", "sha256": "" }
  },
  "tool_identities": [
    { "name": "sp1-verifier",  "version": "6.3.1", "arch": "x86_64",  "artifact_identity": "", "checksum_algorithm": "sha256", "checksum_hex": "", "install_entrypoint": "" },
    { "name": "sp1-verifier",  "version": "6.3.1", "arch": "aarch64", "artifact_identity": "", "checksum_algorithm": "sha256", "checksum_hex": "", "install_entrypoint": "" },
    { "name": "risc0-zkvm",    "version": "3.0.5", "arch": "x86_64",  "artifact_identity": "", "checksum_algorithm": "sha256", "checksum_hex": "", "install_entrypoint": "" },
    { "name": "risc0-groth16", "version": "3.0.4", "arch": "x86_64",  "artifact_identity": "", "checksum_algorithm": "sha256", "checksum_hex": "", "install_entrypoint": "" }
  ],
  "cargo_audit": {
    "version": "0.22.2",
    "crate_sha256": "",
    "source_commit": "",
    "packaged_lock_sha256": ""
  },
  "advisory_db": {
    "repo": "https://github.com/rustsec/advisory-db",
    "commit": "",
    "git_tree": "",
    "content_blake3": ""
  },
  "prover_archives": [
    { "archive_name": "sp1-prover", "arch": "x86_64", "archive_url": "", "archive_sha256": "",
      "members": [
        { "executable_name": "cargo-prove", "member_path": "cargo-prove", "member_sha256": "", "member_size_bytes": 0, "version_argv": "cargo-prove prove --version", "version_output": "", "expected_release_commit": "8252c29", "delivery": "isolated-path" }
      ] },
    { "archive_name": "sp1-prover", "arch": "aarch64", "archive_url": "", "archive_sha256": "",
      "members": [
        { "executable_name": "cargo-prove", "member_path": "cargo-prove", "member_sha256": "", "member_size_bytes": 0, "version_argv": "cargo-prove prove --version", "version_output": "", "expected_release_commit": "8252c29", "delivery": "isolated-path" }
      ] },
    { "archive_name": "risc0-toolchain", "arch": "x86_64", "archive_url": "", "archive_sha256": "",
      "members": [
        { "executable_name": "cargo-risczero", "member_path": "cargo-risczero", "member_sha256": "", "member_size_bytes": 0, "version_argv": "cargo-risczero risczero --version", "version_output": "", "expected_release_commit": "3.0.5", "delivery": "isolated-path" },
        { "executable_name": "r0vm", "member_path": "r0vm", "member_sha256": "", "member_size_bytes": 0, "version_argv": "r0vm --version", "version_output": "", "expected_release_commit": "3.0.5", "delivery": "risc0-server-path" }
      ] }
  ]
}
```

The exact keys `verify_pins.sh` reads (any absent/empty value fails closed):
`base_image`; `base_index_digest`; `base_digest.<arch>`; `apt.debian_url`,
`apt.debian_inrelease_sha256`, `apt.debian_security_url`,
`apt.debian_security_inrelease_sha256`; `rustup_init.version`, `rustup_init.<arch>.url`
and `rustup_init.<arch>.sha256` (per arch — the exact immutable installer URL to fetch
*and* its expected `sha256`); each `tool_identities[i]` with `name`, `version`,
`arch`, `artifact_identity`, `checksum_algorithm` (must be `sha256`), `checksum_hex`,
`install_entrypoint`; `cargo_audit.version`, `cargo_audit.crate_sha256`,
`cargo_audit.source_commit`, `cargo_audit.packaged_lock_sha256`; `advisory_db.repo`,
`advisory_db.commit`, `advisory_db.git_tree`, `advisory_db.content_blake3`; and, per
`prover_archives[i]`, `arch` + `archive_sha256` and, per `members[j]`, `executable_name`,
`member_path`, `member_sha256`, `member_size_bytes`, `version_argv`, `version_output`,
`expected_release_commit`, and `delivery`. `<arch>` is `x86_64` and `aarch64`.

The `cargo_audit` + `advisory_db` blocks bind the Stage-2 supply-chain auditor and the
database it runs against. `cargo-audit` runs INSIDE the pinned builder image with the
advisory DB mounted **READ-ONLY** and `--no-fetch --stale` (the structured, non-executable
audit policy — never an operator-supplied command string), so the scan can neither fetch,
update, nor mutate the pinned database.

**cargo-audit executable identity — source pins vs venue evidence.** The auditor's identity is
split deliberately, because a binary compiled from source at the venue is not, by itself, an
owner-preregistered artifact:

- **Owner-ratified source inputs** (verified by `verify_pins.sh`): the crate + `version`, the
  `.crate` `crate_sha256`, the packaged `packaged_lock_sha256`, and the Rust toolchain + build
  environment (the same pinned `rustup`/`cargo 1.88.0` builder the rest of B0-PRE uses).
- **Venue evidence** (bound into the Stage-2 record, NOT a source pin): the exact installed
  executable `cargo_audit_executable_sha256` and the `cargo audit --version` output.
- **Point of use:** the executable hash is recomputed at the moment of the scan and must match
  the venue-recorded value.
- **Independent reproduction:** a second, independent, SAME-ARCHITECTURE operator MUST reproduce
  the executable identity from the ratified source inputs. If the two same-arch builds do NOT
  reproduce, the first observed binary hash is **not** blessed retroactively — the run stops and
  either an immutable first-party binary is distributed and pinned, or a stronger build-provenance
  model is bound. `verify_pins.sh` therefore never treats the executable SHA as a pin; it verifies
  the source inputs, and the executable identity is established by venue evidence + reproduction.

The Stage-2 record binds the cargo-audit version + executable SHA-256 (venue evidence, above) and
the advisory-DB `commit` + `git_tree` + `content_blake3`.

Required tool-identity coverage: `sp1-verifier` for **both** architectures, and
`risc0-zkvm` + `risc0-groth16` for **x86_64 only**. Anything less fails closed; a RISC
Zero entry declaring `aarch64` is refused outright.

### Declarative prover provisioning (how `prover_archives` is consumed in-image)

The prover executables are provisioned into each candidate builder by **declarative, verified
archive-member extraction** — never a `curl | tar` entrypoint and never `rzup` (production never
invokes it). The mechanism is one staged, self-contained script,
`scripts/provision_prover_toolchain.sh`, which `stage_context.sh` copies **byte-identically** into
the curated Docker build context (`provisioning/provision_prover_toolchain.sh`, its bytes folded
into `staged_context_blake3`) and both Dockerfiles `COPY` + run. It is the SAME file the host
crafted-archive suite (`tests/verified_extraction.test.sh`) exercises — there is no second,
unverified implementation, and the Dockerfiles do **not** call host `lib.sh`. Given a downloaded
archive and the complete declared member set it, in order: (1) verifies the whole-archive
`archive_sha256` **before** extraction; (2) enumerates every entry and refuses symlinks/hardlinks,
absolute paths, `..` traversal, duplicates, and any regular member that is not declared (and
requires every declared member present); (3) extracts **only** the declared members; (4) verifies
each member's `member_size_bytes` + `member_sha256` **before** `chmod`; (5) places it and re-hashes
at the point of use.

Canonical, deterministic in-image paths (Item 7 — fixed, no wall-clock / host-generated locations):

| Executable | Delivery | In-image location |
|------------|----------|-------------------|
| `cargo-prove` (SP1, x86_64 + aarch64) | `isolated-path` | `/opt/b0pre/prover-bin/cargo-prove` (on the production PATH) |
| `cargo-risczero` (RISC Zero, x86_64) | `isolated-path` | `/opt/b0pre/prover-bin/cargo-risczero` (on the production PATH) |
| `r0vm` (RISC Zero, x86_64) | `risc0-server-path` | `/opt/b0pre/risc0-server/r0vm` = `RISC0_SERVER_PATH` |

`cargo-audit` is **built in each Debian builder** from the verified crate + packaged lock (pin 6)
into `/opt/b0pre/audit-prefix/bin/cargo-audit`; the Ubuntu host binary is never copied in. Each
provisioned executable's SHA-256 is recorded in-image under `/opt/b0pre/evidence/` as **venue
evidence** (reproduced by an independent same-arch operator), never a source pin. All build scratch
(downloaded archives, crate build dir, cargo caches) is removed **in the same layer** so the
two-clean-build manifest-equality gate is not weakened.

**Builder-image capability preflight (Item 6).** Before Stage 2 / Stage 5 run, each verified builder
image is asserted — as early as possible, under the production non-login `bash -c` (RT-2) — to carry
its pinned capabilities, validating VERSIONS/IDENTITIES via each tool's exact declared `version_argv`
(never a bare `command -v`). A mis-provisioned image fails closed here, not deep inside a stage:

| Candidate / arch | Required capabilities (identity + version) |
|------------------|--------------------------------------------|
| `sp1` x86_64 | `cargo`, `cargo-audit`@version, `cargo-prove` carrying SP1 release commit |
| `sp1` aarch64 | `cargo`, `cargo-audit`@version, `cargo-prove` carrying SP1 release commit |
| `risc0` x86_64 | `cargo`, `cargo-audit`@version, `cargo-risczero`@`3.0.5`, `r0vm`@`3.0.5` at `RISC0_SERVER_PATH` |
| `risc0` aarch64 | `cargo`, `cargo-audit`@version (RISC Zero prover **not** provisioned — x86_64-only; the arm64 risc0 image records the builder manifest only) |

The ratified build inputs derived from this record are `RUSTUP_INIT_URL` +
`RUSTUP_INIT_SHA256` (per arch), the four `APT_*` fields (identical on both hosts), and
one tool-identity file per (candidate, architecture) named by
`SP1_TOOL_IDENTITY_X86_64`, `SP1_TOOL_IDENTITY_AARCH64`, `RISC0_TOOL_IDENTITY_X86_64`.
Each tool-identity file MUST carry an `"arch"` field; the producer selects it only after
the native-architecture gate passes and refuses a file whose declared arch is not the
host's, so a swapped or cross-architecture identity fails before any download or build.

## Provenance policy (what a clean verification does and does not establish)

`verify_pins.sh` establishes that each pinned artifact's bytes match the value the owner
proposes, fetched from an allow-listed primary source over https (or, for the two apt
snapshot URLs, from an immutable snapshot service whose `InRelease` is both OpenPGP-signed
and hash-pinned). That is a **checksum trust model**, and for some upstreams it is the
strongest chain available:

- The Debian base image carries in-toto SBOM **attestations** published by the registry.
- The Debian snapshots are **OpenPGP-signed** and verified by apt.
- `rustup-init` has a publisher-published `.sha256` sidecar but **no signature**.
- **SP1 and RISC Zero publish no author signature and no build-provenance attestation**
  for their release artifacts.

For SP1 and RISC Zero the owner has confirmed ratification on this basis, and only this
basis: the **primary GitHub release asset**, the **GitHub-published asset digest**, an
**independent re-download and re-hash**, the **release tag-to-commit mapping**, and the
**binary's self-reported identity**. That combination is recorded as **checksum
provenance, not signed provenance**. It must never be described as signed provenance, and
a successful download is never by itself provenance.

### The APT http bootstrap exception

The two pinned `snapshot.debian.org` locators — and nothing else — may use plain http,
because the pinned base image has no `ca-certificates` before the first package
installation. `verify_pins.sh` still requires the initial host to be exactly
`snapshot.debian.org`, refuses any other http host, refuses a redirect off the pinned
snapshot host, and refuses an https→http downgrade. Integrity comes from the pinned
`InRelease` sha256 plus apt's OpenPGP verification, both enforced before any package is
installed. http therefore permits denial-of-service or replay attempts, but not
accepted-content substitution. The exception is never generalized to Rust, GitHub,
container registries, or tool artifacts — see VENUE.md §3 for the full statement.

## Verification (automated)

```sh
# resolves every pin from its primary source and fails closed on any mismatch;
# prints a PASS/FAIL line per pin. Requires network + docker + a sha256 tool + curl.
bash tools/b0-pre-candidates/scripts/verify_pins.sh proposed-pins.json
```

`verify_pins.sh` never edits any repo file and never "accepts" a pin — it only reports
whether each proposed value matches its primary source. A clean run is a *precondition*
for ratification, not ratification itself.

## Ratification (owner only — not performed here)

After a clean `verify_pins.sh` run on an independent host, the owner ratifies by placing
the verified values into a `pins.env` the runbook sources (kept out of the committable set
until the B0-PRE PR path calls for it). This DRAFT proposes; it does not ratify.
