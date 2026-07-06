# SUM Chain Release Process

How an approved change becomes a released change. This documents the **current,
manual** process. It does not describe automated CI/CD, artifact signing, a
changelog, tag automation, or package-publishing pipelines — those are not part
of this repository today, and this file is not aspirational.

For how decisions are made and recorded, see [GOVERNANCE.md](GOVERNANCE.md).

## Record-first releases

On-chain governance **records** approval; it does not release anything by
itself and does not force validators to upgrade (see
[GOVERNANCE.md](GOVERNANCE.md)). A passed proposal is an authoritative approval
record. Maintainers and validators then carry the change out off-chain. The one
exception is a passed `TreasurySpend` + `OnChain` proposal, which performs a
single native-Koppa treasury payout on-chain — see
[GOVERNANCE.md](GOVERNANCE.md#execution-model). Nothing else auto-executes.

## Making a change

Changes are proposed and reviewed as described in
[CONTRIBUTING.md](CONTRIBUTING.md):

- Branch off `main`; do not commit directly to `main`.
- Keep commits focused with clear messages.
- Open a pull request; ensure the workspace builds and the relevant tests pass
  before requesting review.

```bash
cargo build            # whole workspace
cargo test             # full suite (prefer -p <crate> while iterating)
cargo clippy -p <crate> --all-targets
cargo fmt --all
```

## Versioning

This is a single Cargo workspace with one shared version, currently **`0.1.0`**
(`[workspace.package]` in `Cargo.toml`). The project is **pre-1.0**: no semantic
versioning stability guarantees are made, and interfaces may change between
versions. There is no separate changelog or release-tag process in this
repository.

## From approval to release, by change type

Approved governance proposals map to concrete off-chain actions:

- **Repository / process, RPC-surface, token/economic changes** — a code pull
  request per [CONTRIBUTING.md](CONTRIBUTING.md). Economic changes should be
  reconciled against
  [docs/architecture/economic-model.md](docs/architecture/economic-model.md).
- **Genesis / config / validator and activation-height changes** — a
  byte-identical runtime-genesis edit plus a **coordinated validator restart**.
  Follow [docs/operations/production-checklist.md](docs/operations/production-checklist.md)
  (Genesis, Mainnet Parameters, and Restart & Rollback Coordination). Validators
  choose to adopt the change; governance does not force it.
- **Consensus / wire / storage migrations** — a binary rollout coordinated
  across validators, per the production checklist.
- **Package publishing** — carried out off-chain by maintainers.
- **Emergency / security** — the validator-quorum fast-path (a threshold of the
  active validator set signs; admin/council authority is validator-quorum
  controlled, no single council address); report vulnerabilities privately per
  [SECURITY.md](SECURITY.md).

## Activating a dormant subprotocol (incl. governance)

Subprotocols such as on-chain governance ship **dormant** and are enabled only
by a coordinated activation: a byte-identical runtime-genesis change that sets
the activation gate (for governance, `governance_enabled_from_height`) and any
required parameters (`ChainParams.governance`), rolled out with validator
coordination. No activation height is proposed here. See
[docs/operations/production-checklist.md](docs/operations/production-checklist.md)
for the activation and rollback procedure, and [GOVERNANCE.md](GOVERNANCE.md)
for what governance does once enabled.

## Related documents

- [GOVERNANCE.md](GOVERNANCE.md) — governance model and proposal lifecycle.
- [CONTRIBUTING.md](CONTRIBUTING.md) — build/test and pull-request process.
- [docs/operations/production-checklist.md](docs/operations/production-checklist.md) — launch, activation, and rollback operations.
- [SECURITY.md](SECURITY.md) — vulnerability reporting.
