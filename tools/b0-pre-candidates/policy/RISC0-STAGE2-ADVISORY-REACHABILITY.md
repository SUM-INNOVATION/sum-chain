# RISC0 Stage-2 advisory reachability evidence (frozen)

Frozen reachability analysis backing the two structured advisory exceptions in
`stage2-advisory-exceptions.json`. The `source_feature_graph_hash` field of each exception is the
BLAKE3 of THIS file; any edit invalidates the binding and forces re-review.

**Scope.** RISC0 candidate only. SP1 resolves neither vulnerable version and carries zero findings
(and, by policy, zero exceptions). The evidence was frozen from the exact RISC0 proof-stack graph
that Stage-2 audits (`candidates/risc0` two-member workspace: `host` = risc0-zkvm 3.0.5 +
risc0-groth16 3.0.4 + risc0-build 3.0.5; `guest` = risc0-zkvm-platform 2.2.3), reproduced from the
actual host proving runner (`risc0-zkvm = "=3.0.5"`, default features, the same graph the prover
executes). `cargo tree` edges below are normal (compiled) edges.

The bar: "not compiled into the guest" is INSUFFICIENT, because the host prover also executes in
production. For each crate we establish it is **compiled but its vulnerable code path is not
exercised in this execution mode** (default local proving: `default_prover()` → `ExternalProver` →
the pinned `r0vm`; no `BONSAI_API_URL`; `RISC0_HOME` pre-provisioned; `RISC0_BUILD_LOCKED=1`; the
terminal Groth16 backend runs `--network none` under the Docker firewall).

---

## RUSTSEC-2023-0071 — `rsa 0.9.10` (Marvin timing side-channel; crypto-failure)

**Dependency path (normal edges):**
```
rsa 0.9.10
└── rzup 0.5.2
    ├── risc0-build 3.0.5
    │   └── risc0-zkvm 3.0.5
    └── risc0-zkvm 3.0.5 (client feature)
```

**Vulnerable usage.** `rsa` is used by `rzup` (the RISC Zero toolchain manager) to verify RSA
signatures on **downloaded toolchain archives**.

**Reachability determination — COMPILED, NOT EXERCISED.** Per owner decision B, the guest toolchain
(r0.1.91.1) is provisioned once by verified-tree extraction into an isolated `RISC0_HOME`; the guest
is built `RISC0_BUILD_LOCKED=1` against that home with **no rzup network resolution and no toolchain
downloads** (no rzup exec, no inherited `~/.risc0`, no mutable-tag resolution). rzup is used
filesystem-only (read `settings.toml` / the default version). No download occurs, so rzup's RSA
signature-verification code path — the only path that invokes `rsa` — is never executed. The
terminal backend additionally runs with `--network none`.

---

## RUSTSEC-2025-0055 — `tracing-subscriber 0.2.25` (ANSI-escape log injection; format-injection)

**Dependency path (normal edges):**
```
tracing-subscriber 0.2.25
└── ark-relations 0.5.1          (optional dep, feature-enabled)
    ├── ark-crypto-primitives 0.5.0
    │   └── ark-groth16 0.5.0
    │       └── risc0-groth16 3.0.5
    │           └── risc0-zkvm 3.0.5
    └── ark-snark 0.5.1
```

**Vulnerable usage.** The advisory affects `tracing-subscriber`'s fmt layer when it **formats
untrusted input containing ANSI escape sequences**.

**Reachability determination — COMPILED, NOT EXERCISED.**
1. There is exactly **one** `tracing-subscriber` version in the graph (0.2.25), reached only through
   the arkworks constraint-system crate `ark-relations` (an optional dep it enables) — it is not a
   live logging subscriber selected by risc0-zkvm.
2. **No fmt subscriber is initialized anywhere in the compiled host graph** (no
   `tracing_subscriber::fmt` / `FmtSubscriber` / `fmt::init` in risc0-zkvm's host sources or in
   ark-relations). The prover-runner registers none. With no subscriber registered, the vulnerable
   ANSI-formatting code is never executed (linked but uncalled).
3. The actual Groth16 stark-to-snark is performed by the **pinned docker rapidsnark backend**
   (evidenced by the firewall's recorded `docker run risczero/risc0-groth16-prover …` call), not by
   the host `ark-groth16` Rust path.
4. Even were a subscriber active, the proving path processes only the frozen, trusted
   statement/witness — no untrusted external input reaches any log, so the injection vector is absent.

---

## Applicability & review triggers

Both exceptions are valid ONLY while the execution model above holds. They MUST be re-reviewed on
any change to: the SDK (`risc0-zkvm` / `risc0-groth16` version), the affected crate version, the
feature set, the proving runner, the resolved lockfile, or the execution mode (e.g. switching to
Bonsai remote proving, which WOULD exercise `rsa`, or initializing a fmt subscriber over untrusted
input, which WOULD exercise the `tracing-subscriber` path). Stage-2 additionally fails closed
automatically if the exact affected crate+version is absent from the resolved graph (stale binding),
if the bound SDK version is not resolved, or if any advisory without a matching exception appears.
