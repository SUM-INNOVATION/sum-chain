# Azure migration packet: two validators, native systemd

**Status: a plan, nothing executed.** No Azure resource exists yet, no
validator has been stopped, and no key has moved. Every step below needs a
separate authorization, given at the time. The native release comes from
PR #263 (`release-native.yml`). That PR is unmerged, and no release has been
published.

## 0. Blockers found against PR #263 (read first)

1. **#263's preflight is for an in-place upgrade on one host, not a move to a
   new one.** `native-preflight-record.sh --phase before` requires the unit to
   be active with a main process ("has no main process" otherwise).
   `native-preflight.py` requires:
   - `--expected-current-sha256`: the binary running *on that host*;
   - a rollback copy on the same host whose tree digest equals the data
     directory's;
   - a preserved old binary hashing as that current binary.

   A fresh Azure VM has no running unit and no old binary, and its rollback
   is the old VM, not a local copy. So **the preflight cannot pass as
   specified on the new VMs.** This is a missing capability, not a code
   defect, and #263 is left unchanged. What still applies, and how the gap
   is covered here, is shown in §9. Covering it by code needs a follow-up
   PR adding a migration mode that records the source host's
   stopped-phase facts and the target's pre-start facts, and compares them.
2. **Migrating and upgrading at once skips the mixed-version check.** In the
   in-place plan, one validator runs Stage 1 while the other still runs
   0.2.0, and any consensus difference shows up as a rejected import. If both
   validators come up on Azure running Stage 1, nothing checks Stage 1
   against 0.2.0. **Recommended:** migrate first with the exact binary
   production runs, then upgrade in place on Azure with #263's preflight
   unchanged.
   - The catch: the running binary was compiled **on Ubuntu 26.04** and may
     need a newer glibc than Ubuntu 24.04's 2.39.
   - Check it read-only on the old hosts before choosing:
     `objdump -T <exe> | grep -oE 'GLIBC_[0-9.]+' | sort -Vu | tail -1`.
   - If it needs more than 2.39, the old binary cannot run on the target,
     and the only rollback is the old VMs (§11).
3. **The release doesn't exist yet.** #263 needs approval, an authorized
   merge and an authorized `release-native.yml` dispatch. Until the
   `release-<commit>` assets are published and verified, there is nothing
   to install. A migration "tomorrow" depends on all three.
4. **The second validator (GW1p…) has never been inspected.** Its binary,
   commit, genesis hash, config, database size and role are unknown. §5 and
   §6 cannot be completed without them.
5. **The inspected host also runs nginx on port 80.** It likely fronts the
   public RPC. This specification has no public RPC endpoint (RPC and health
   stay on loopback). Decide where public RPC goes before the old host is
   retired.

## 1. Azure resources (Portal settings, per validator)

| setting | validator A (listener) | validator B (dialer) |
|---|---|---|
| resource group / region | one RG, **one region** | same |
| availability zone | zone 1 | **zone 2** |
| image | Ubuntu Server 24.04 LTS, x64, **Gen2** | same |
| security type | Trusted launch (Secure Boot, vTPM) | same |
| size | **Standard_D2as_v5** (2 vCPU, 8 GiB) | same |
| priority | Regular (**no Spot**) | same |
| auth | SSH public key only; password login off | same |
| public inbound ports (wizard) | **None**; use the NSG in §2 | same |
| OS disk | **Standard SSD**, 32 GiB (E4), platform-managed key, delete-with-VM **off** | same |
| data disk | new, **Premium SSD P10, 128 GiB**, LRS, same zone as the VM, host caching **None**, LUN 0, delete-with-VM **off** | same |
| NIC | **accelerated networking on** | same |
| public IP | **Standard SKU, static**, zonal (same zone), delete-with-VM **off** | same |
| boot diagnostics | managed storage account | same |
| patching | **manual orchestration**: no automatic reboots (a reboot halts the chain) | same |
| extensions | none | same |

Before provisioning, confirm Standard_D2as_v5 is offered in both zones of the
chosen region (`az vm list-skus -l <region> --size Standard_D2as_v5 --zone`)
and that vCPU quota exists.

## 2. Network security group (one per NIC)

| priority | direction | source | port | action |
|---|---|---|---|---|
| 100 | in | operator allowlist (CIDR list, `/32` each) | TCP 22 | allow |
| 110 | in | the **other validator's static IP** | TCP 9933 (p2p) | allow |
| 120 | in | any other approved p2p peers, by `/32` | TCP 9933 | allow (only if listed) |
| 4096 | in | any | any | deny (explicit, beside Azure's default) |
| out | | | any | allow (default) |

RPC `127.0.0.1:8545` and health, readiness and metrics `127.0.0.1:8546` are
bound to loopback in the config, so they are unreachable whatever the NSG
says. Do **not** open 8545, 8546 or 80. Check from outside after start:
`nc -vz <ip> 8545 8546` must fail.

## 3. Data disk and filesystem layout

```bash
lsblk -o NAME,SIZE,TYPE,MOUNTPOINT,SERIAL        # find the 128G LUN0 disk; never format the OS disk
sudo mkfs.ext4 -L sumchain-data /dev/disk/azure/scsi1/lun0   # (or the /dev/disk/azure/data/by-lun/0 path)
sudo mkdir -p /var/lib/sumchain
echo 'LABEL=sumchain-data /var/lib/sumchain ext4 defaults,noatime,nofail 0 2' | sudo tee -a /etc/fstab
sudo mount -a && findmnt /var/lib/sumchain
sudo useradd --system --home /var/lib/sumchain --shell /usr/sbin/nologin sumchain
sudo install -d -o sumchain -g sumchain -m 0750 /var/lib/sumchain/data /var/lib/sumchain/rollback
sudo install -d -o root -g sumchain -m 0750 /etc/sumchain
sudo install -d -o sumchain -g sumchain -m 0700 /etc/sumchain/keys
```

| path | disk | contents |
|---|---|---|
| `/opt/sumchain/releases/<commit>/` | OS | release binaries, read-only (install-native.sh) |
| `/etc/sumchain/config.toml`, `genesis.json` | OS | config 0640, genesis 0644 |
| `/etc/sumchain/keys/` | OS | validator key, 0600, owner `sumchain` |
| `/var/lib/sumchain/data` | **data** | RocksDB, including `node.key` (the libp2p identity) |
| `/var/lib/sumchain/rollback` | **data** | pre-start copy of the transferred data |

## 4. Native release and systemd

1. On an operator workstation:
   - download `release-<commit>`;
   - `native-release.py verify`;
   - `verify-attestation.sh --file` on every asset;
   - note the sha256 of `SHA256SUMS`.
2. Copy the assets to the VM and install them. The archive is picked by
   `uname -m`, and nothing is compiled on the VM:
   ```bash
   sudo tools/release/install-native.sh --release-dir <assets> --commit <C> --prefix /opt/sumchain \
     --sums-sha256 <sha256 of the verified SHA256SUMS>
   ```
3. `/etc/systemd/system/sumchain.service`, a new unit rather than a drop-in:
   ```ini
   [Unit]
   Description=SUM Chain validator node
   After=network-online.target var-lib-sumchain.mount
   Wants=network-online.target
   RequiresMountsFor=/var/lib/sumchain
   [Service]
   Type=simple
   User=sumchain
   Group=sumchain
   WorkingDirectory=/var/lib/sumchain
   ExecStart=/opt/sumchain/releases/<C>/sumchain run --config /etc/sumchain/config.toml --genesis /etc/sumchain/genesis.json
   Restart=on-failure
   RestartSec=5
   TimeoutStopSec=90
   LimitNOFILE=65536
   NoNewPrivileges=true
   ProtectSystem=strict
   ReadWritePaths=/var/lib/sumchain
   PrivateTmp=true
   [Install]
   WantedBy=multi-user.target
   ```
   There is no `KillSignal` line: the release handles SIGTERM. The unit stays
   **disabled** until §8.
4. `config.toml` changes from the old one only as listed:
   - `data_dir = "/var/lib/sumchain/data"`;
   - `validator_key = "/etc/sumchain/keys/<file>"`;
   - `[rpc] addr = "127.0.0.1:8545"`;
   - **`[health] addr = "127.0.0.1:8546"`**;
   - the dialer's bootnode, now the listener's new static IP with the
     **same peer ID**. It is preserved because `node.key` moves with the
     data.

## 5. Moving keys without reading them

- An operator runs every key step; the keys are never printed, read into a
  terminal or passed through chat.
- Copy host-to-host over SSH, preserving mode, with no agent forwarding, and
  compare **hashes only**:
  ```bash
  # on the old host, as the service user:
  sha256sum <keydir>/<file> | cut -c1-16        # a prefix is enough to compare
  scp -p -o ForwardAgent=no <keydir>/<file> <new-host>:/tmp/k.$$ \
    && ssh <new-host> 'sudo install -o sumchain -g sumchain -m 0600 /tmp/k.* /etc/sumchain/keys/<file> && shred -u /tmp/k.*'
  # on the new host:
  sudo sha256sum /etc/sumchain/keys/<file> | cut -c1-16   # must equal the old prefix
  ```
- `node.key` moves inside the data directory (§7) and is compared the same
  way.
- **One key never runs in two places.** Before any new unit starts, the old
  unit is `disable`d and `mask`ed. Two live copies of one validator key
  produce conflicting blocks at its slots.

## 6. Genesis and config: exact comparison

On each old host and each new VM (sha256 only; contents never printed):
- `genesis.json`:
  - **both old hosts must have the same hash** (the inspected host has
    `404cfab9…1234`);
  - each new VM must have that exact hash;
  - the copy is byte for byte (`scp -p`), never re-formatted or regenerated.
- `config.toml`: its hash changes by design (§4). Compare the settings
  instead. Section and key **names** must be the old set plus `[health]`.
  Check the values of `chain`-affecting keys by eye on the operator's own
  screen, not in any shared log.
- After start, `chain_getChainParams` from a new node must equal the old
  node's capture from before the halt (`jq -S` diff, runbook §2.7/§4.3).

## 7. Database transfer: two passes, the last after a clean stop

1. **Pass 1, while the old node runs:**
   `rsync -aHAX --numeric-ids <old data>/ <new>:/var/lib/sumchain/data/`.
   The copy is inconsistent at this point; the pass only shortens the halt.
2. **Halt.** Stop the old node **with SIGINT**: the deployed binary ignores
   SIGTERM.
   ```bash
   sudo systemctl kill -s SIGINT sumchain.service
   until ! systemctl is-active -q sumchain.service; do sleep 1; done
   ```
   Then disable and mask the unit.
3. **Pass 2, final:**
   `rsync -aHAX --numeric-ids --delete --checksum <old data>/ <new>:/var/lib/sumchain/data/`.
4. **Prove the copy is exact.** Compute the tree digest on both sides; it
   must be identical:
   `cd <dir> && find . -type f ! -name LOCK -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum`.
   This is the same digest #263's preflight uses.
5. **Take the rollback copy on the VM:**
   `cp -a /var/lib/sumchain/data /var/lib/sumchain/rollback/data-<ts>`, then
   compare its digest again.
6. Set ownership: `chown -R sumchain:sumchain /var/lib/sumchain`.

## 8. Startup order, from topology

**Today's topology (inspection, 2026-09-26):** 7jUZ… is the dialer, since
bootnodes are configured, and GW1p… is on the other host. GW1p…'s role must
be confirmed from its own config before the window.

Rule: **the listener must be running before the dialer starts.**

1. **Stop both old nodes.** SIGINT, then the listener second, so the halt
   starts once.
2. Run the final passes (§7) for both.
3. **Start the listener's VM first:**
   ```bash
   systemctl unmask …; systemctl enable --now sumchain
   ```
   Wait until its log shows the database opened, its peer ID unchanged, and
   `/health` 200 on loopback.
4. **Then start the dialer's VM.** It dials the listener's new static IP.
5. Blocks resume when both are connected. Record the halt as the time from
   the first SIGINT to the first new block.

## 9. Preflight, as it applies to a new host

`native-preflight.py` in full applies to the **in-place** upgrade (blocker
0.2). For this move, the same facts are checked by hand, in this order, and
every one is a no-go if it fails (§12):

| check | on | how |
|---|---|---|
| old binary, old genesis, old config hash | old host, before halt | `native-preflight-record.sh --phase before` (works on the old host; its release/health failures are expected there and ignored) |
| process exited, lock free | old host, after SIGINT | `native-preflight-record.sh --phase stopped` |
| data copied exactly | old host vs new VM | tree digests equal (§7.4) |
| rollback copy exact | new VM | tree digest (§7.5) |
| release binary for this machine | new VM | `install-native.sh` passed; `/opt/sumchain/releases/<C>/sumchain --version` |
| genesis identical | all four | sha256 (§6) |
| health on loopback | new VM | `[health] addr = "127.0.0.1:8546"` in config |
| capacity | new VM | `lsmem`: 8 GiB online (floor 4 GiB); data disk ~124 GiB free for a 3.9 GiB database |
| keys identical, old unit masked | both | hash prefixes (§5); `systemctl is-enabled` = `masked` |

## 10. Pre-migration snapshot and rollback rehearsal

- **Old hosts:** take a provider snapshot of each old VM's disk *after* the
  clean stop and *before* the Azure nodes start. This is a second rollback
  path besides the preserved VMs.
- **Azure:** after §7, take an incremental snapshot of each data disk.
- **Rehearsal, before the window:**
  1. Create a disk from the Azure snapshot and attach it to a scratch VM.
  2. Mount it read-only and check the tree digest equals the source's.
  3. Time the whole cycle. The times go in the rehearsal record.

  The rehearsal must never start a node with the production key.

## 11. Rollback

The old VMs are untouched by Stage 1: their data directories are only ever
read by `rsync`. **Never copy an Azure (Stage-1-touched) directory back to
an old host.**

1. Stop both Azure nodes with `systemctl stop` (graceful on SIGTERM), then
   disable and mask them.
2. On the old hosts: `systemctl unmask`, then start the listener first, then
   the dialer.
3. Their data resumes at the height of the final pass. Every block the Azure
   pair produced is abandoned. That rewinds the chain and is an **owner
   decision**, as with any both-validator rollback.

## 12. After start: verification (each new VM)

| check | pass |
|---|---|
| identity | the newest "Produced block" height's proposer = the expected public key (7jUZ… or GW1p…) |
| peers | `get_p2p_stats`: connected 1; dialer outbound 1, listener inbound 1 |
| head | `sum_blockNumber` advances; both nodes within 2 blocks |
| finality | `get_finality`: finalized = head − 6, and advancing |
| state | a finalized block's `state_root` equal on both nodes |
| health | loopback `/health` 200, `/ready` 200; `nc` from outside to 8545/8546 fails |
| metrics | `wave1-monitor.sh verify http://127.0.0.1:8546` passes |
| binary | `/proc/<pid>/exe` sha256 = the release record's x86_64 binary; `--version` = `sumchain <C>` |
| memory | node RSS well under 8 GiB; `free` shows no swap use |
| disk | `df /var/lib/sumchain` has growth room; the database is on the data disk (`findmnt -T`) |
| logs | no "attempting repair", no "REFUSING", no import errors |

## 13. Old VMs: preserve for 48–72 hours

- Units stay **masked**, and the VMs stay **powered on**, so SSH and the
  disks remain available.
- **Delete nothing:** not the data, not the binary, not the snapshots.
- Revoke no key yet, and release no IP.
- After 72 h of healthy Azure operation, and only with the owner's
  decision: power off, keep the snapshots per retention policy, then
  decommission.

## 14. No-go: stop the migration if any of these holds

- #263 is not approved and merged, or `release-<C>` is not published and
  verified: the archive, `SHA256SUMS` and every attestation.
- GW1p…'s host has not been inspected, or its genesis hash differs from
  7jUZ…'s.
- The decision in blocker 0.2 (migrate as-is, or migrate and upgrade at once)
  is not made. If "as-is", the glibc check fails.
- Standard_D2as_v5 is unavailable in two zones of the region, or quota is
  missing.
- Any tree digest, genesis hash or key-hash prefix differs between old and
  new.
- An old unit is not masked before a new one starts, so one key could run in
  two places.
- `[health]` is not on loopback, or 8545, 8546 or 80 is reachable from
  outside.
- The old node did not exit cleanly, or its database lock is still held,
  before the final pass.
- The provider snapshot of either old VM is missing, or the Azure snapshot
  rehearsal was not run and timed.
- The public-RPC decision (blocker 0.5) is not made.
- The halt budget is exceeded, with no first new block within 15 minutes of
  the first SIGINT. Roll back per §11 only with the owner's decision.
