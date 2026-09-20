# The supported validator memory floor: 4 GiB

> **Decision, for this release:** **4 GiB (4,294,967,296 bytes) is the supported
> validator memory floor.** A validator is supported on 4 GiB or more of memory
> available to the node process. Below that, the deployment is outside what this
> release supports.
>
> **It is an OPERATIONAL minimum. It is NOT consensus.** Nothing in the protocol
> reads it, nothing enforces it, no node is refused for having less, and no
> block is invalid because a node had less. A validator with less memory is a
> deployment this project does not support — it is not an ineligible validator,
> and it is not producing invalid blocks.

This page is deliberate and visible because the decision **contradicts what
parts of this tree currently say.** Three places state that no validator RAM
minimum exists. They are named and reconciled below rather than left to be
discovered as a contradiction.

---

## Why the floor is stated at all

The block write-set ceiling — `MAX_BLOCK_WRITE_SET_BYTES`, 256 MiB — is a
SAFETY ceiling **derived from a 4 GiB validator memory envelope**. That
derivation has been in the tree, and until now it rested on an assumption with
nothing behind it: the tree asserted a 4 GiB envelope in a test while
simultaneously stating, in the b0-pre protocol artifact, that no validator
memory minimum exists.

Stating the floor closes that gap. The derivation is not new; what is new is
that the number it divides by is now something the project says, rather than
something a test assumed.

---

## What the floor is, precisely

| property | value |
|---|---|
| floor | **4 GiB = 4,294,967,296 bytes** |
| kind | **operational minimum** |
| consensus-enforced | **no** |
| eligibility gate | **no** |
| detected at runtime | **no** — nothing probes host memory |
| enforced by | the deployment manifests, as a cgroup request and limit |

Explicitly, and in the terms the b0-pre documents use:

* It is **not** a consensus rule. No `ChainParams` field carries it, it is not
  folded into `Genesis::activation_digest` or into
  `protocol_digest::consensus_limits`, and no node compares it with a peer.
* It is **not** a validator eligibility gate. Qualification remains
  performance-based. A node with less memory that keeps the verification pace
  is not disqualified by anything.
* It is **not** the b0-pre `reference_memory_bytes` envelope promoted into a
  requirement. That figure exists for a different purpose (controlled
  candidate comparison) and happens to be the same number; see the
  reconciliation below.
* It **is** the supported deployment configuration: the memory a validator
  operator should provision, and the number the block write-set ceiling is
  derived against.

---

## Reconciling the three places that deny a floor exists

All three deny a **consensus / eligibility** hardware minimum. None of them is
wrong, and none of them is edited by this decision. What they do NOT say — and
what a reader could reasonably take them to say — is that no *operational*
supported minimum exists either. It now does.

| # | where | what it says | how it reconciles |
|---|---|---|---|
| 1 | `docs/b0-pre/protocol/b0-pre-protocol-v1.json`, `qualification_gates.validator_eligibility` (line 773) | "performance-based, not hardware-class-based: no minimum physical cores or RAM … A node of any CPU/RAM configuration may participate; `reference_cpuset_cores` / `reference_memory_bytes` are only the controlled candidate-comparison envelope, not a deployment or consensus hardware minimum." | Still true as written, about **eligibility**. The 4 GiB floor gates nothing: no node is refused, no block is invalid. The sentence and the floor are about different things, and neither is weakened. |
| 2 | `docs/b0-pre/venue/VENUE.md` (validators bullet, §"Resource-neutrality") | the same claim in prose | **Edited.** The bullet now names the operational floor alongside the eligibility statement, so a reader of VENUE.md does not leave believing no supported minimum exists. |
| 3 | `docs/b0-pre/protocol/b0-pre-protocol-v1.schema.json`, `QualificationGates.description` (line 920) | "These are performance gates, not hardware-class gates: neither validators nor contributors have a CPU/RAM minimum." | Still true as written, about **qualification gates**. Not edited; see the constraint below. |

### Why (1) and (3) are not edited, stated rather than glossed

Both are machine-locked, and editing either is a re-ratification, not a
documentation change:

* `b0-pre-protocol-v1.json` is the owner-ratified normative artifact. Its whole
  content is the canonical hash preimage, and the resulting
  `b0_pre_spec_hash` is `e933e7325c2639a48d8e25f20746d0f8abc822dee9fcfa87c2e6cdec226cf2a2`,
  committed in `b0-pre-protocol-v1.json.hash` and asserted three ways by
  `tools/b0-pre-validator/tests/protocol_hash.rs::ratified_finalized_produces_the_real_spec_hash`.
  Changing one character of `validator_eligibility` changes the ratified spec
  hash.
* `b0-pre-protocol-v1.schema.json` is byte-locked to the typed Rust model
  (`tools/b0-pre-validator/tests/protocol_schema.rs::schema_byte_locked_to_typed_model`);
  its text is generated from a doc comment in
  `tools/b0-pre-validator/src/protocol.rs` and cannot be edited in place.

So the reconciliation is not "the b0-pre documents were updated". It is: **the
b0-pre statements are about eligibility and remain exactly true; the floor is
operational and is stated here and in VENUE.md and in the manifests.** If the
project later wants the ratified artifact itself to carry the operational
floor, that is a spec re-ratification with a new `b0_pre_spec_hash`, and it is
deliberately not being done under cover of a documentation pass.

---

## Every shipped manifest, checked against the floor

Every deployment manifest in this tree that sets a memory request or limit for
a validator:

| manifest | container | request (before → after) | limit | satisfies 4 GiB |
|---|---|---|---|---|
| `deploy/kubernetes/statefulset.yaml` | validator | `1Gi` → **`4Gi`** | `4Gi` | yes, after the change |
| `deploy/kubernetes/statefulset-validator-1.yaml` | validator | `1Gi` → **`4Gi`** | `4Gi` | yes, after the change |
| `deploy/kubernetes/statefulset-validator-2.yaml` | validator | `1Gi` → **`4Gi`** | `4Gi` | yes, after the change |
| `deploy/kubernetes/statefulset-validator-3.yaml` | validator | `1Gi` → **`4Gi`** | `4Gi` | yes, after the change |
| `docker-compose.yaml` | validator-1/2/3, fullnode | none set | none set | n/a — sets no memory bound at all |
| `deploy/snip-local-mirror.yaml` | single validator | none set | none set | n/a — a CI devnet preset, explicitly not production-like |

There is no Helm chart in this tree; `deploy/kubernetes/` and the two compose
files are the whole manifest surface.

### What was wrong, and why the limit alone was not enough

All four StatefulSets already carried `limits.memory: "4Gi"`. All four carried
`requests.memory: "1Gi"`, and **that is the setting that made the floor
untrue.** In Kubernetes:

* `limits.memory` is the cgroup ceiling — exceed it and the container is
  OOM-killed. It bounds the node from above; it guarantees nothing.
* `requests.memory` is what the scheduler reserves. With a 1Gi request the pod
  is placed on a node that only ever guaranteed it 1 GiB, and its QoS class is
  **Burstable** — so under node memory pressure the kubelet evicts it as soon
  as it is above its request, which can be at 1.1 GiB, long before the 4 GiB
  limit.

A validator that can be evicted at 1 GiB does not have a 4 GiB envelope, and a
256 MiB write-set ceiling derived from 4 GiB is not conservative for it. Setting
`requests.memory` equal to `limits.memory` makes the pod **Guaranteed** QoS for
memory, which is what actually reserves the floor.

The compose files set no memory bound, so nothing in them contradicts the
floor. They are local/CI presets;
`deploy/snip-local-mirror.yaml`'s own header says it is not production-like.
Neither is a shipped validator deployment.

---

## The relationship to the 256 MiB write-set ceiling

`MAX_BLOCK_WRITE_SET_BYTES = 1 << 28` (268,435,456 B = 256 MiB) is unchanged by
this decision and must stay unchanged. The relationship the project relies on,
plainly:

1. **256 MiB is a conservative SAFETY ceiling derived from the 4 GiB floor.**
   The largest single row a block can still commit is `C / 2`, because the
   overlay charges both the new value and the captured pre-image. During that
   commit, peak live memory is `2 x C` = **512 MiB**, which is **12.5% of the
   4 GiB envelope** and exactly the `4 GiB / 8` budget the derivation allots one
   block's execution. Measured and printed by
   `crates/state/tests/block_write_set_ceiling.rs::the_ceiling_keeps_one_blocks_peak_live_memory_inside_the_assumed_budget`:

   ```
   SAFETY: ceiling 268435456 B (256 MiB); largest committable row 134217728 B;
   worst-case peak live 536870912 B (512 MiB) = 12.5% of the 4294967296 B cgroup
   envelope; budget 536870912 B (512 MiB)
   ```

2. **It is explicitly NOT a sufficiency bound.** 256 MiB is not "the amount of
   write set a block needs". Sufficiency is a separate, measured question, and
   the measurement is not close: a full block at this chain's declared limits
   (`max_block_bytes: 2,000,000`, `max_txs_per_block: 1,000`) costs
   **8,072,363 B** against the 256 MiB ceiling — **33.3x headroom**
   (`a_full_block_at_the_chains_declared_limits_publishes_with_the_derived_headroom`).
   The ceiling is set by what a validator's memory can survive, not by what a
   block needs.

3. **The 4 GiB floor is what makes the derivation coherent for the first time.**
   Before this decision the safety half divided by a number the project did not
   claim: the test asserted a 4 GiB envelope from the manifests while the
   b0-pre artifact stated that no validator memory minimum existed, and the
   manifests themselves only *requested* 1 GiB. Now the divisor is a stated,
   supported floor, and the manifests reserve it. **Raising the floor is the
   only way to raise the ceiling**; lowering the floor invalidates the ceiling
   and forces a re-derivation.

4. **The ceiling is comparable between binaries, and the floor is not.** The
   ceiling is folded into `protocol_digest::consensus_limits` by name and value,
   so two binaries enforcing different block applicability cannot report the
   same protocol digest. The floor is folded into nothing, because it decides
   nothing about a block. That asymmetry is the point: consensus-relevant
   numbers must be comparable, operational ones must be documented.

### The tests that hold each part

| what | test |
|---|---|
| the ceiling is in the protocol digest, by name and value | `crates/state/tests/block_write_set_ceiling.rs::the_ceiling_is_folded_into_the_protocol_digest_by_name` |
| the 4 GiB envelope is still what the manifests enforce | `crates/state/tests/block_write_set_ceiling.rs::the_recorded_validator_memory_envelope_is_still_what_the_derivation_assumed` |
| peak live memory at the ceiling stays inside the budget | `crates/state/tests/block_write_set_ceiling.rs::the_ceiling_keeps_one_blocks_peak_live_memory_inside_the_assumed_budget` |
| the ceiling is large enough for a full block | `crates/state/tests/block_write_set_ceiling.rs::a_full_block_at_the_chains_declared_limits_publishes_with_the_derived_headroom` |
| the block limits the derivation assumed are still in `genesis.json` | `crates/state/tests/block_write_set_ceiling.rs::the_block_limits_the_derivation_was_taken_against_are_still_what_genesis_json_declares` |

`the_recorded_validator_memory_envelope_is_still_what_the_derivation_assumed`
reads `memory: "4Gi"` out of all four StatefulSets. It is the mechanical guard
on this decision: lowering the manifests below the floor fails a test rather
than passing review.

---

## What this does NOT settle

`ACTIVATION-AUDIT` row **AL-13** asks whether arbitrary input can reach an
allocator abort, and it needs three numbers: the maximum reachable row size, the
allocation factor, and the memory a validator is specified to have. This
decision supplies the third. It does **not** close AL-13: the growth-to-abort
arithmetic over all three numbers has not been performed, and that arithmetic —
not a missing memory figure — is now the whole of what the row is waiting on.
AL-13 stays UNDETERMINED, for a different reason than before.

---

## Related

* [p2p-admission-and-compatibility.md](p2p-admission-and-compatibility.md)
* [production-checklist.md](production-checklist.md)
* `docs/b0-pre/protocol/VALIDATOR-MEMORY-FLOOR-RECONCILIATION.md` — the same
  reconciliation, placed beside the ratified artifact it is about.
