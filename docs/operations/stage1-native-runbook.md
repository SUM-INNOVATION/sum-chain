# Stage 1 native rollout runbook — systemd, native binary, both Linux architectures

**This is the production runbook.** Production runs a native binary under
systemd, established by a read-only inspection on 2026-09-26 (§1). The
Kubernetes procedure in [stage1-rollout-runbook.md](stage1-rollout-runbook.md)
does not describe production. Its findings about the database, SIGTERM and
halts still apply, but its commands do not.

Nothing here has been run against production. Every step that changes the
host needs the owner's authorization at the time.

## 1. What production is (inspected 2026-09-26, read-only, one of two validators)

| | inspected host (validator 7jUZ…) |
|---|---|
| platform | Ubuntu 26.04 LTS, kernel 7.0, **x86_64**, OpenStack KVM guest, 2 vCPU |
| memory | `free` reports 3.7 GiB total (MemTotal); installed memory not yet measured (§6) |
| process model | **native binary under systemd** (`sumchain.service`); no Docker, containerd, Kubernetes or registry credentials |
| how it was installed | **compiled on the host** from a source checkout at `d40d2db20a74746ac4c9239783614684c6e7a417` (2026-07-10), with the host's own cargo |
| running binary | sha256 `d832bbde2d1f81d02f698f6de4d357911c9c492cf07a522f4b7363ae337984f7`, reports 0.2.0, no embedded commit |
| unit | `Restart=on-failure`, `RestartSec=5`; stops with SIGTERM (the default), `TimeoutStopSec=90s` |
| config | has **no `[health]` section**. RPC is bound to loopback |
| genesis (this validator) | sha256 `404cfab9768a83e839a90c3450a6d026aefbf911094b08d4ca04dd1984105234`; differs from the committed file |
| database | 3.9 GiB, on the root ext4 filesystem; 15 GiB free; no separate volume; no backup tooling |
| topology | **dialer**: bootnodes configured, 1 outbound connection, 0 inbound |
| other validator | GW1p… is on another machine; not inspected |

No addresses, host names, account names or key paths are recorded here. The
sanitized raw evidence is kept outside the repository.

## 2. What the release is

- **Artifact:** the GitHub Release `release-<commit>`, published by
  `.github/workflows/release-native.yml`. It carries:
  - an x86_64 and an aarch64 archive;
  - an SPDX SBOM and SLSA provenance for each;
  - `SHA256SUMS` and `release-record.txt`;
  - GitHub attestations for every asset and both binaries, verified against
    `release-native.yml@refs/heads/main`.

  See [release-image.md](release-image.md) §0.
- **Build:** compiled on GitHub's native x86_64 and aarch64 runners, **never
  on a validator.**
- **Install:** `tools/release/install-native.sh` picks the archive from
  `uname -m`, so no operator names an architecture. It installs side by side
  into `/opt/sumchain/releases/<commit>/` and never touches the service.

## 3. Hazards this procedure is built around

1. **The deployed binary must never open a database Stage 1 has touched.**
   This was reproduced against the deployed revision `d40d2db`; the evidence
   is in `evidence/stage1-downgrade-d40d2db-2026-09-26/`.
   - `d40d2db` knows 184 column families. Stage 1 creates five more on its
     first open: `application_journal`, `beacon_state`, `beacon_state_diffs`,
     `compute_pool_state` and `compute_pool_state_diffs`.
   - `d40d2db` treats the resulting "Invalid argument" as corruption and runs
     `DB::repair`. That rewrites the database's manifest from 189 families to
     10 and moves the old manifests and WAL into `lost/`. It then **fails
     again and exits 1, on every start**.
   - Under `Restart=on-failure` that becomes a repair-and-crash loop, and with
     two validators the chain halts.
   - No rows were lost in the reproduction (all nine non-empty families
     byte-identical), and the Stage 1 binary still opens the repaired database
     at the same height, hash, state root and finality. But the old binary
     cannot run on it at all.
   - Restoring the pre-upgrade copy into a **new** directory works: `d40d2db`
     opens it with no repair and resumes at the copy's height.
   - The earlier reproduction against `8abbd304` (one extra family) found a
     silent repair and a divergent chain instead. Either way, a rollback is a
     restore, never a restart of the old binary on the touched directory.
2. **The deployed binary ignores SIGTERM.** `systemctl stop` on the old
   binary waits 90 s, then SIGKILLs it with no flush. For the last stop of the
   old binary, send SIGINT (§5.3). From Stage 1 on, the node handles SIGTERM
   gracefully and exits 0 (`crates/node/tests/graceful_shutdown.rs`), so the
   unit needs **no** `KillSignal` override.
3. **Health would be public.** Without a `[health]` section, Stage 1 binds
   health, readiness and `/metrics` to `0.0.0.0:8546`. The preflight fails
   until the config binds them to loopback, or to an address the owner
   deliberately chose and protected (§5.1).
4. **One validator down halts the chain.** Both halts, the upgrade and any
   rollback, are planned outages.

## 4. Topology and restart order, derived rather than assumed

A node with bootnodes configured **dials** at startup, then re-dials every
30 s. A node without bootnodes **listens**. Measured locally: a restarted
listener waited 19.3 s for the dialer's redial, while a restarted dialer
reconnected in 5.5 s.

`native-preflight.py` records each host's role from its configuration and its
connections, and prints the order. Neither public identity is a role: the
roles belong to the configuration and can change.

Rule: **the listener must be running before the dialer starts.**
- Restart the listener first. If it is restarted while the dialer runs, the
  dialer reconnects on its next redial, within about 30 s.
- Start the dialer only when the listener is up.

On the inspected pair today, 7jUZ… dials and GW1p… listens, so GW1p… is
upgraded first. Confirm that from GW1p…'s own preflight record before
relying on it.

## 5. Procedure (per validator, listener first)

### 5.1 Before anything is stopped

1. On a workstation, verify the release: `native-release.py verify`, and
   `verify-attestation.sh --file` on every asset.
2. Copy only the assets to the host and install them side by side:
   ```bash
   tools/release/install-native.sh --release-dir <assets> --commit <C> --prefix /opt/sumchain \
     --sums-sha256 <sha256 of the SHA256SUMS whose attestation you verified>
   ```
3. Add the owner-authorized health binding to the config:
   `[health] addr = "127.0.0.1:8546"`.
4. Record and check the running phase:
   ```bash
   tools/lane-b/native-preflight-record.sh --phase before --out before.record \
     --installed /opt/sumchain/releases/<C>/sumchain
   python3 tools/lane-b/native-preflight.py --before before.record \
     --expected-current-sha256 d832bbde… --expected-current-commit d40d2db… \
     --expected-genesis-sha256 <production hash> --release-record release-record.txt --release-commit <C>
   ```
   It must print the running-phase pass, and it prints this node's role and
   the restart order.

### 5.2 The halt

1. **Stop the old binary with SIGINT**, then make sure systemd agrees it has
   stopped:
   ```bash
   sudo systemctl kill -s SIGINT sumchain.service
   while systemctl is-active -q sumchain.service; do sleep 1; done
   ```
2. **Make the rollback copy while stopped**, into a new directory on the
   same filesystem, and preserve the old binary:
   ```bash
   cp -a <data_dir> <rollback>/data-<ts>
   cp -p <old executable> <rollback>/sumchain-d832bbde
   ```
3. Record and check the stopped phase:
   ```bash
   tools/lane-b/native-preflight-record.sh --phase stopped --out stopped.record \
     --rollback-copy <rollback>/data-<ts> --rollback-binary <rollback>/sumchain-d832bbde
   python3 tools/lane-b/native-preflight.py --before before.record --stopped stopped.record …
   ```
   It must print `PREFLIGHT COMPLETE`:
   - the process has exited and the lock is free;
   - the copy's tree digest equals the data directory's;
   - the preserved binary hashes as the rollback target;
   - the disk still holds a restore copy and growth.
4. Switch the unit to the verified release with the drop-in
   `deploy/systemd/sumchain-release.conf`. Keep every argument the unit
   already has, then `sudo systemctl daemon-reload`.
5. Start it: `sudo systemctl start sumchain.service`. Then check:
   - `--version` of the running `/proc/<pid>/exe` is the release commit;
   - `/health`, `/ready` and `/metrics` answer on loopback, and
     `wave1-monitor.sh verify` passes;
   - blocks are imported and produced.

### 5.3 Rollback

Only with the owner's decision. It rewinds the chain if both validators roll
back.

1. Stop Stage 1 cleanly: `sudo systemctl stop sumchain.service`. SIGTERM is
   graceful now; wait until it is inactive.
2. Move the Stage-1-touched data directory aside and **never open it with the
   old binary**:
   `mv <data_dir> <rollback>/data-stage1-touched-<ts>`.
3. Restore the pre-upgrade copy into a new directory at the data path:
   `cp -a <rollback>/data-<ts> <data_dir>`.
4. Restore the exact old binary:
   - remove the drop-in;
   - check that the unit's ExecStart file hashes `d832bbde…` (restore it from
     `<rollback>/sumchain-d832bbde` if not);
   - `sudo systemctl daemon-reload`.
5. Start the old service. Confirm its log shows **no** "attempting repair" and
   that it loads the copy's height.

## 6. Capacity

On the inspected host: 2 vCPU, a 3.9 GiB database, 15 GiB free on the root
ext4 filesystem, no separate data volume.
- A local rollback copy (3.9 GiB) plus a restore copy (3.9 GiB) plus growth
  (at least 2 GiB) needs about 9.8 GiB, which fits.
- The preflight refuses whenever it no longer would.

**Memory floor.** The supported floor is 4 GiB of memory the validator is
provisioned with ([validator-memory-floor.md](validator-memory-floor.md)).
`free` showed 3.7 GiB, which is `MemTotal`: installed memory minus what the
kernel reserves for itself (kernel image, page tables and, on Ubuntu, a
crash-kernel reservation).
- A 4 GiB VM normally reports roughly 3.6–3.8 GiB there. So 3.7 GiB is
  *consistent with* a nominal 4 GiB machine, but does not prove it.
- The deciding figure is installed memory, "Total online memory" from
  `lsmem`, which the preflight records and requires to be at least 4 GiB.
- Until the next read-only inspection reads it, **the host's compliance with
  the floor is undetermined.** The floor is not lowered to fit.

## 7. Still needed from production

From **both** validators:
- the preflight records;
- the genesis hash, which must be byte-identical;
- installed memory (`lsmem`);
- the health-binding change, as authorized.

From **GW1p…'s** host, everything in §1: platform, process model,
binary, commit, config/genesis hashes, database size, free disk and role.

Plus the remaining production-only items:
- a rehearsed restore with timings;
- `cf::STATE` counts before and after;
- OC-3 and SC-8 evidence.
