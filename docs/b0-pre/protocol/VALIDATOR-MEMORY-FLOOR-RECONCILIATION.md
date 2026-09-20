# The 4 GiB validator memory floor, beside the artifact that denies one

This note sits next to `b0-pre-protocol-v1.json` because that file is the place
a reader most likely goes to find out whether validators have a RAM minimum, and
the answer it gives is now incomplete on its own.

**The decision, for this release:** 4 GiB is the supported validator memory
floor. It is an **operational** minimum. It is not consensus, not an eligibility
gate, and not enforced by any code path. The full statement is
`docs/operations/validator-memory-floor.md`; this note exists only so the
question cannot be answered from the artifact alone and come out wrong.

## What the artifact says, and why it is still correct

`qualification_gates.validator_eligibility` (line 773):

> "Validator qualification is performance-based, not hardware-class-based: no
> minimum physical cores or RAM, and detected host hardware is never an
> eligibility gate. A node of any CPU/RAM configuration may participate;
> reference_cpuset_cores / reference_memory_bytes are only the controlled
> candidate-comparison envelope, not a deployment or consensus hardware
> minimum."

`qualification_gates.scope` (line 774) repeats "This is a candidate-comparison
envelope, not a validator hardware minimum", and the generated schema's
`QualificationGates` description (`b0-pre-protocol-v1.schema.json`, line 920)
repeats it a third time.

**All three remain true, and none of them is contradicted.** They are statements
about ELIGIBILITY:

| the artifact says | the floor does |
|---|---|
| no minimum RAM to participate | nothing refuses a node for having less |
| detected host hardware is never an eligibility gate | nothing detects host memory at all |
| `reference_memory_bytes` is not a deployment or consensus minimum | the floor is not that field, re-labelled |
| insufficient performance is an operational-liveness condition | the floor is an operational condition of the same kind |

The floor is a support and provisioning statement. It gates nothing, is folded
into no digest, and is compared by no node against any peer.

## Why `reference_memory_bytes` and the floor are the same number

They are both 4 GiB, and it would be easy — and wrong — to conclude that one was
quietly promoted into the other.

* `reference_memory_bytes: 4294967296` is the memory limit the chain-side
  verification run is **pinned to** so that two proof candidates are compared
  under identical conditions. Its purpose is comparability.
* The operational floor is the memory a validator deployment is **provisioned
  with**, and it is the envelope `MAX_BLOCK_WRITE_SET_BYTES` (256 MiB) is
  derived from: the worst-case peak live memory of one block at the ceiling is
  512 MiB, one eighth of 4 GiB.

They coincide because a comparison envelope that a supported deployment could
not actually establish would be useless, not because either was derived from the
other. The artifact's own rule already requires `configured limits <= detected
resources`; a supported deployment is one on which that is satisfiable for the
pinned envelope.

## Why this artifact is not edited

`b0-pre-protocol-v1.json` is the owner-ratified normative artifact. Its entire
content is the canonical hash preimage, and the resulting `b0_pre_spec_hash` is

```
e933e7325c2639a48d8e25f20746d0f8abc822dee9fcfa87c2e6cdec226cf2a2
```

committed in `b0-pre-protocol-v1.json.hash` and asserted three separate ways by
`tools/b0-pre-validator/tests/protocol_hash.rs::ratified_finalized_produces_the_real_spec_hash`
— against the value the crate computes, against the sidecar file, and against
the committed JSON re-parsed from disk. Editing one character of
`validator_eligibility` changes the ratified spec hash.

`b0-pre-protocol-v1.schema.json` is byte-locked to the typed Rust model by
`tools/b0-pre-validator/tests/protocol_schema.rs::schema_byte_locked_to_typed_model`;
its prose is generated from a doc comment in
`tools/b0-pre-validator/src/protocol.rs` and cannot be edited in place at all.

So stating the floor inside the artifact is a **spec re-ratification with a new
`b0_pre_spec_hash`**, not a documentation edit. That is a decision of its own and
is deliberately not being taken under cover of a documentation pass. If the
project later wants the artifact to carry the operational floor, this note
records exactly what that would cost.

`docs/b0-pre/venue/VENUE.md` carries no hash and has been edited: its validators
bullet now states both halves.

## Where the floor is actually enforced

Not here, and not in any protocol code — in the deployment manifests, as a
cgroup reservation:

* `deploy/kubernetes/statefulset.yaml`
* `deploy/kubernetes/statefulset-validator-1.yaml`
* `deploy/kubernetes/statefulset-validator-2.yaml`
* `deploy/kubernetes/statefulset-validator-3.yaml`

each of which sets `requests.memory: "4Gi"` **and** `limits.memory: "4Gi"`. The
request was `1Gi` before this release, which meant the floor the write-set
ceiling is derived from was not actually reserved: the scheduler reserved 1 GiB
and the kubelet could evict the pod as soon as it went above that.

**These pods are Burstable, not Guaranteed.** An earlier revision of this file
called these pods Guaranteed QoS on the strength of the memory pair alone.
They are not, because
the same containers set `requests.cpu: 500m` against `limits.cpu: 2000m` and
Guaranteed requires equality on BOTH resources in EVERY container. What the
equal memory pair does buy is the thing that matters here: kubelet
node-pressure eviction does not evict a pod whose usage does not exceed its
requests, and with request == limit this container cannot exceed its memory
request without first exceeding its identical memory limit. The 4 GiB is
reserved and protected on the eviction path regardless of the pod-level label.
The full treatment, including the kernel-OOM residual Burstable does cost, is
in `docs/operations/validator-memory-floor.md`.

`crates/state/tests/block_write_set_ceiling.rs::the_recorded_validator_memory_envelope_is_still_what_the_derivation_assumed`
reads the `4Gi` limit out of all four and fails if it moves.
