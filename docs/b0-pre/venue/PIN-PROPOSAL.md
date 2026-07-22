# B0-PRE immutable venue-input pin proposal (DRAFT — not ratified)

Status: **DRAFT / NOT RATIFIED.** This document defines the *primary sources* and the
*automated verification* for every immutable venue input the authoritative run consumes.
It deliberately contains **no concrete pin values** — no digests, checksums, or URLs are
inserted here, and nothing in `VENUE.md` / the scripts is changed. Values are proposed,
verified against their primary source by `scripts/verify_pins.sh`, and only then submitted
for owner ratification in a separate step.

Bound to canonical commit `5994bed018fdf38d4913b5b166dd5a662d9cf919`.

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
| 1 | `BASE_IMAGE` + `BASE_DIGEST` (per-arch) | the base image's registry, resolved **by digest** | `docker manifest inspect "$BASE_IMAGE@$BASE_DIGEST"` must resolve; the returned manifest's `platform.architecture` must equal the target arch; digest must be a full `sha256:<64hex>` (never a tag) |
| 2 | `APT_SNAPSHOT` | the distro's immutable snapshot service (e.g. a dated `snapshot.debian.org` / `snapshot.ubuntu.com` URL) | the snapshot URL is reachable, immutable (date-pinned, not a rolling mirror), and produces a byte-identical package index across two fetches |
| 3 | `RUSTUP_INIT_SHA256` (per-arch) | the official Rust release channel (`static.rust-lang.org/rustup/.../rustup-init`) for **Rust 1.88.0** | download `rustup-init` for the arch, recompute `sha256`, compare to the proposed value |
| 4 | SP1 tool identity — `sp1-verifier 6.3.1` | the pinned SP1 release artifact (its immutable download URL / registry identity) | download the declared `artifact_identity`, recompute the declared `checksum_algorithm` checksum, compare to the declared `checksum_hex` |
| 5 | RISC Zero tool identities — `risc0-zkvm 3.0.5`, `risc0-groth16 3.0.4` | the pinned RISC Zero release artifacts | same download → recompute → compare as (4), per tool |

Notes:
- The **base image** identity IS the pinned base digest; its provenance is the
  base-resolution command/output, distinct from the builder's two-build evidence (VENUE.md §3).
- `RUSTUP_INIT_SHA256` gates that Rust **1.88.0** is installed *inside* the builder by
  exact release + checksum, never assumed present (VENUE.md §1).
- Tool identities are fail-closed: a version string alone never preregisters the bytes;
  authoritative assembly refuses any absent/synthetic value (VENUE.md §3.5).

## Proposed-value file (operator fills; kept OUT of the repo until ratified)

`verify_pins.sh` reads a proposed-pins file of this shape (example keys, **no values**):

```json
{
  "base_image": "",
  "base_digest": { "x86_64": "", "aarch64": "" },
  "apt_snapshot": "",
  "rustup_init_sha256": { "x86_64": "", "aarch64": "" },
  "tool_identities": [
    { "name": "sp1-verifier",  "version": "6.3.1", "artifact_identity": "", "checksum_algorithm": "sha256", "checksum_hex": "", "install_entrypoint": "" },
    { "name": "risc0-zkvm",    "version": "3.0.5", "artifact_identity": "", "checksum_algorithm": "sha256", "checksum_hex": "", "install_entrypoint": "" },
    { "name": "risc0-groth16", "version": "3.0.4", "artifact_identity": "", "checksum_algorithm": "sha256", "checksum_hex": "", "install_entrypoint": "" }
  ]
}
```

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
