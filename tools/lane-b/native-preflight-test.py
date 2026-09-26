#!/usr/bin/env python3
"""Battery for the native (systemd) preflight: native-preflight.py and
native-preflight-record.sh. NONPRODUCTION fixtures only.

The checker cases run anywhere. The recorder cases need GNU coreutils and a
Linux-style /proc (they run in CI on Linux; elsewhere they are reported as
skipped, never as passed): systemctl, journalctl, curl and lsmem are shimmed,
while the executable, config, genesis, data directory and its LOCK are real
files, and a real process holds the lock for the "held" case.

    python3 tools/lane-b/native-preflight-test.py
"""
from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
CHECKER, RECORDER = HERE / "native-preflight.py", HERE / "native-preflight-record.sh"
GiB = 1024 ** 3
OLD = "d" * 64                                  # NONPRODUCTION hashes and commits
NEW86, NEWARM = "a" * 64, "b" * 64
GEN = "9" * 64
RC = "c" * 40
RESULTS: list[tuple[str, bool, str]] = []


def rec(**kw) -> str:
    return "".join(f"{k}: {v}\n" for k, v in kw.items())


def before(**over) -> dict:
    r = dict(phase="before", unit="sumchain.service", unit_active="active", unit_user="svc",
             unit_working_directory="/srv/node", executable="/srv/node/sumchain", executable_sha256=OLD,
             running_image_sha256=OLD, executable_version="none (pre-release binary; node_info 0.2.0)",
             source_checkout_commit="e" * 40, config_sha256="1" * 64, genesis_sha256=GEN,
             health_addr="127.0.0.1:8546", data_dir="/srv/node/data", data_bytes=str(int(3.9 * GiB)),
             disk_available_bytes=str(15 * GiB), mem_total_bytes=str(int(3.7 * GiB)),
             mem_installed_online_bytes=str(4 * GiB), memory_max="infinity", bootnodes_configured="yes",
             p2p_outbound="1", p2p_inbound="0", validator_pubkey="6407afe6" + "0" * 56, machine="x86_64",
             installed_binary="/opt/sumchain/releases/" + RC + "/sumchain", installed_binary_sha256=NEW86,
             installed_binary_version=f"sumchain {RC}")
    r.update(over)
    return r


def stopped(**over) -> dict:
    r = dict(phase="stopped", unit="sumchain.service", unit_active="inactive", executable_sha256=OLD,
             process_exited="yes", db_lock="free", data_dir="/srv/node/data", data_tree_sha256="7" * 64,
             rollback_copy="/srv/node/rollback/data", rollback_copy_tree_sha256="7" * 64,
             rollback_copy_bytes=str(int(3.9 * GiB)), rollback_copy_same_fs="yes",
             disk_available_after_copy_bytes=str(int(11.1 * GiB)), rollback_binary="/srv/node/rollback/sumchain",
             rollback_binary_sha256=OLD)
    r.update(over)
    return r


RELEASE = rec(release_commit=RC, x86_64_binary_sha256=NEW86, aarch64_binary_sha256=NEWARM)


def checker(tmp: Path, b: dict | None, s: dict | None, *extra: str, release: str = RELEASE,
            args: dict | None = None) -> tuple[int, str]:
    (tmp / "before.record").write_text(rec(**b) if b is not None else "")
    (tmp / "release-record.txt").write_text(release)
    a = {"--expected-current-sha256": OLD, "--expected-genesis-sha256": GEN, "--release-commit": RC,
         "--release-record": str(tmp / "release-record.txt")}
    a.update(args or {})
    argv = [sys.executable, str(CHECKER), "--before", str(tmp / "before.record")]
    if s is not None:
        (tmp / "stopped.record").write_text(rec(**s))
        argv += ["--stopped", str(tmp / "stopped.record")]
    for k, v in a.items():
        if v is not None:
            argv += [k, v]
    p = subprocess.run(argv + list(extra), capture_output=True, text=True)
    return p.returncode, p.stdout + p.stderr


def case(name: str, want: int, text: str, b=None, s=None, *extra, **kw):
    tmp = Path(tempfile.mkdtemp(prefix="preflight-"))
    try:
        code, out = checker(tmp, b if b is not None else before(), s, *extra, **kw)
        RESULTS.append((name, code == want and text in out, out.strip()[-300:]))
    finally:
        shutil.rmtree(tmp)


def checker_cases():
    case("running-phase checks pass", 0, "running-phase checks pass")
    case("both phases pass", 0, "the new binary may be started", before(), stopped())
    case("the current binary's hash is required", 1, "STOP: --expected-current-sha256",
         args={"--expected-current-sha256": None})
    case("the production genesis hash is required", 1, "STOP: --expected-genesis-sha256",
         args={"--expected-genesis-sha256": None})
    case("the release record must be for the release commit", 1, "the release record is for",
         release=rec(release_commit="f" * 40, x86_64_binary_sha256=NEW86))
    case("a provider snapshot needs a restore rehearsal", 1, "go together",
         args={"--provider-snapshot": "snap-1"})
    case("another executable than expected", 1, "IDENTITY: the unit's executable",
         before(executable_sha256="e" * 64, running_image_sha256="e" * 64))
    case("the running image differs from the file on disk", 1, "running process image differs",
         before(running_image_sha256="f" * 64))
    case("the checkout is at another commit", 1, "IDENTITY: checkout at",
         args={"--expected-current-commit": "0" * 40})
    case("genesis differs from production", 1, "GENESIS MISMATCH", before(genesis_sha256="8" * 64))
    case("the installed binary is the other architecture's", 1, "RELEASE: the installed binary hashes",
         before(installed_binary_sha256=NEWARM))
    case("an aarch64 host takes the aarch64 binary, no operator input", 0, "aarch64",
         before(machine="aarch64", installed_binary_sha256=NEWARM))
    case("arm64 is aarch64", 0, "arm64 -> aarch64", before(machine="arm64", installed_binary_sha256=NEWARM))
    case("an unsupported machine", 1, "no release archive for machine", before(machine="riscv64"))
    case("the installed binary reports another commit", 1, "reports",
         before(installed_binary_version="sumchain " + "0" * 40))
    case("no [health] section: 0.0.0.0:8546 would be exposed", 1, "HEALTH BINDING: the config has no [health]",
         before(health_addr="absent"))
    case("health on every interface", 1, "HEALTH BINDING: health binds 0.0.0.0:8546",
         before(health_addr="0.0.0.0:8546"))
    case("health on a public address the owner chose", 0, "(owner-chosen)",
         before(health_addr="10.0.0.5:8546"), None, "--allow-health-addr", "10.0.0.5:8546")
    case("the owner's choice does not cover another address", 1, "HEALTH BINDING",
         before(health_addr="0.0.0.0:8546"), None, "--allow-health-addr", "10.0.0.5:8546")
    case("health on IPv6 loopback", 0, "[::1]:8546", before(health_addr="[::1]:8546"))
    case("health on localhost", 0, "localhost:8546", before(health_addr="localhost:8546"))
    case("installed memory unknown: MemTotal alone cannot decide", 1, "installed memory is unavailable",
         before(mem_installed_online_bytes="unavailable"))
    case("3.7 GiB installed: below the floor", 1, "below the 4 GiB supported floor",
         before(mem_installed_online_bytes=str(int(3.7 * GiB))))
    case("4 GiB installed, 3.7 GiB usable after kernel reservations: meets the floor", 0, "4.00 GiB installed")
    case("a unit MemoryMax below the floor", 1, "MemoryMax", before(memory_max=str(2 * GiB)))
    case("no room for a rollback copy beside the database", 1, "a safe rollback copy cannot coexist",
         before(data_bytes=str(7 * GiB)))
    case("a provider snapshot needs room only for a restore copy", 0, "running-phase checks pass",
         before(data_bytes=str(7 * GiB)), None, "--provider-snapshot", "snap-1", "--restore-rehearsal", str(CHECKER))
    case("topology: bootnodes configured -> dialer", 0, "this node is the DIALER")
    case("topology: no bootnodes -> listener", 0, "this node is the LISTENER",
         before(bootnodes_configured="no", p2p_outbound="0", p2p_inbound="1"))
    case("topology unknown", 1, "TOPOLOGY", before(bootnodes_configured=""))
    case("stopped: the unit is still active", 1, "STOPPED: the unit is still active", before(),
         stopped(unit_active="active"))
    case("stopped: a process still runs the old executable", 1, "a process still runs", before(),
         stopped(process_exited="no"))
    case("stopped: the database lock is held", 1, "the database lock is 'held'", before(), stopped(db_lock="held"))
    case("stopped: the rollback copy differs from the data", 1, "tree digest differs", before(),
         stopped(rollback_copy_tree_sha256="6" * 64))
    case("stopped: no rollback copy and no provider snapshot", 1, "ROLLBACK COPY: none recorded", before(),
         stopped(rollback_copy_tree_sha256=""))
    case("stopped: the 'copy' is the data directory itself", 1, "the data directory itself", before(),
         stopped(rollback_copy="/srv/node/data"))
    case("stopped: the preserved binary is not the current one", 1, "ROLLBACK BINARY", before(),
         stopped(rollback_binary_sha256="e" * 64))
    case("stopped: no room left for a restore copy", 1, "after the rollback copy", before(),
         stopped(disk_available_after_copy_bytes=str(3 * GiB)))
    case("stopped: the executable changed between the records", 1, "changed between the records", before(),
         stopped(executable_sha256="e" * 64))


# ----------------------------------------------------------------- recorder ---

SYSTEMCTL = r"""#!/usr/bin/env bash
case "$1" in
  is-active) cat "$FX/active" ;;
  show) shift; unit=$1; shift; prop=""; while [[ $# -gt 0 ]]; do [[ $1 == -p ]] && prop=$2; shift; done
        cat "$FX/prop.$prop" 2>/dev/null ;;
  *) exit 1 ;;
esac
"""
JOURNALCTL = '#!/usr/bin/env bash\necho "sumchain::node: Produced block 0xabc at height 77"\n'
CURL = r"""#!/usr/bin/env bash
d=""; while [[ $# -gt 0 ]]; do [[ $1 == -d ]] && d=$2; shift; done
case "$d" in
  *node_info*) echo '{"result":{"version":"0.2.0","current_height":77}}' ;;
  *get_p2p_stats*) echo '{"result":{"outbound_connections":1,"inbound_connections":0}}' ;;
  *get_block_by_height*) echo '{"result":{"proposer":"6407afe6c5f32c678baf1f3c2218362c104865a9ae1ec50d769432d9d0c4baf8"}}' ;;
esac
"""
LSMEM = '#!/usr/bin/env bash\necho "Total online memory:      4294967296"\n'


def host(tmp: Path, *, health: bool = True) -> tuple[Path, dict]:
    """A fake systemd service on disk: executable, config (with a secret-looking
    line the recorder must never copy), genesis, data dir with LOCK, a key dir."""
    wd = tmp / "srv"
    (wd / "data").mkdir(parents=True)
    (wd / "data" / "LOCK").write_text("")
    (wd / "data" / "000001.sst").write_bytes(b"sst bytes")
    (wd / "keys").mkdir()
    (wd / "keys" / "validator.json").write_text("NONPRODUCTION-PRIVATE-KEY")
    (wd / "keys" / "validator.json").chmod(0)
    exe = wd / "sumchain"
    exe.write_text("#!/bin/sh\nexit 1\n")
    exe.chmod(0o755)
    (wd / "genesis.json").write_text('{"chain_id":1}')
    cfg = ('[node]\ngenesis = "genesis.json"\ndata_dir = "data"\nvalidator_key = "keys/validator.json"\n'
           '[network]\nbootnodes = ["/ip4/192.0.2.1/tcp/9933"]\n[rpc]\naddr = "127.0.0.1:8545"\n'
           'api_key = "SECRET-DO-NOT-COPY"\n' + ('[health]\naddr = "127.0.0.1:8546"\n' if health else ''))
    (wd / "config.toml").write_text(cfg)
    fx, proc, shim = tmp / "fx", tmp / "proc", tmp / "shim"
    for d in (fx, proc / "4242", shim):
        d.mkdir(parents=True)
    shutil.copy(exe, proc / "4242" / "exe")
    (proc / "4242" / "status").write_text("VmRSS:\t 512000 kB\n")
    (proc / "meminfo").write_text("MemTotal:  3880000 kB\nMemAvailable: 2900000 kB\n")
    props = {"User": "svc", "WorkingDirectory": str(wd), "KillSignal": "15", "TimeoutStopUSec": "1min 30s",
             "Restart": "on-failure", "MemoryMax": "infinity", "MainPID": "4242", "MemoryCurrent": "600000000",
             "ExecStart": f"{{ path={exe} ; argv[]={exe} run --config config.toml --genesis genesis.json ; "
                          f"ignore_errors=no }}"}
    for k, v in props.items():
        (fx / f"prop.{k}").write_text(v + "\n")
    (fx / "active").write_text("active\n")
    for name, body in (("systemctl", SYSTEMCTL), ("journalctl", JOURNALCTL), ("curl", CURL), ("lsmem", LSMEM)):
        (shim / name).write_text(body)
        (shim / name).chmod(0o755)
    env = dict(os.environ, FX=str(fx), PREFLIGHT_PROC=str(proc), PATH=f"{shim}:{os.environ['PATH']}")
    return wd, env


def record(env: dict, out: Path, *args: str) -> tuple[int, str]:
    p = subprocess.run(["bash", str(RECORDER), "--out", str(out), *args], capture_output=True, text=True, env=env)
    return p.returncode, p.stdout + p.stderr


def recorder_cases():
    if platform.system() != "Linux":
        print("  NOTE  recorder cases not run here (they need GNU coreutils and Linux, and run in CI); "
              "not counted as passed")
        return

    def rcase(name, fn):
        tmp = Path(tempfile.mkdtemp(prefix="preflight-rec-"))
        try:
            ok, detail = fn(tmp)
            RESULTS.append((f"recorder: {name}", ok, detail))
        finally:
            for p in tmp.rglob("*"):
                try:
                    p.chmod(0o700)
                except OSError:
                    pass
            shutil.rmtree(tmp)

    def before_ok(tmp):
        wd, env = host(tmp)
        code, out = record(env, tmp / "b.rec", "--phase", "before")
        text = (tmp / "b.rec").read_text() if code == 0 else out
        want = ["health_addr: 127.0.0.1:8546", "bootnodes_configured: yes", "mem_installed_online_bytes: 4294967296",
                "running_image_sha256: ", "validator_pubkey: 6407afe6", "p2p_outbound: 1", "unit_user: svc"]
        missing = [w for w in want if w not in text]
        return code == 0 and not missing, f"missing {missing}: {text[-300:]}"
    rcase("the before-phase record holds the facts", before_ok)

    def no_secrets(tmp):
        wd, env = host(tmp)
        code, out = record(env, tmp / "b.rec", "--phase", "before")
        text = (tmp / "b.rec").read_text() if code == 0 else ""
        leaked = [s for s in ("SECRET-DO-NOT-COPY", "NONPRODUCTION-PRIVATE-KEY", "192.0.2.1") if s in text + out]
        return code == 0 and not leaked, f"leaked {leaked}"
    rcase("never copies config values, key contents or peer addresses", no_secrets)

    def no_keys_read(tmp):
        body = "\n".join(l for l in RECORDER.read_text().splitlines() if not l.lstrip().startswith("#"))
        bad = [w for w in ("keys/", "validator_key", "environ", "printenv", " env ", "sudo") if w in body]
        return not bad, f"the recorder mentions {bad}"
    rcase("never reads the key directory, process environments, or uses sudo", no_keys_read)

    def health_absent(tmp):
        wd, env = host(tmp, health=False)
        code, _ = record(env, tmp / "b.rec", "--phase", "before")
        return code == 0 and "health_addr: absent" in (tmp / "b.rec").read_text(), ""
    rcase("an absent [health] section is recorded as absent", health_absent)

    def stopped_ok(tmp):
        wd, env = host(tmp)
        (Path(env["FX"]) / "active").write_text("inactive\n")
        shutil.copytree(wd / "data", tmp / "copy")
        old = tmp / "old-sumchain"
        shutil.copy(wd / "sumchain", old)
        code, out = record(env, tmp / "s.rec", "--phase", "stopped", "--rollback-copy", str(tmp / "copy"),
                           "--rollback-binary", str(old))
        text = (tmp / "s.rec").read_text() if code == 0 else out
        r = dict(l.split(": ", 1) for l in text.splitlines() if ": " in l)
        ok = (code == 0 and r.get("process_exited") == "yes" and r.get("db_lock") == "free"
              and r.get("data_tree_sha256") == r.get("rollback_copy_tree_sha256")
              and r.get("rollback_binary_sha256") == r.get("executable_sha256"))
        return ok, text[-400:]
    rcase("stopped: exited, lock free, copy digest equals the data, binary preserved", stopped_ok)

    def lock_held(tmp):
        wd, env = host(tmp)
        holder = subprocess.Popen([sys.executable, "-c",
                                   "import fcntl,os,sys,time; fd=os.open(sys.argv[1], os.O_RDWR); "
                                   "fcntl.lockf(fd, fcntl.LOCK_EX); print('locked', flush=True); time.sleep(30)",
                                   str(wd / "data" / "LOCK")], stdout=subprocess.PIPE, text=True)
        try:
            holder.stdout.readline()
            code, out = record(env, tmp / "s.rec", "--phase", "stopped")
            return code == 0 and "db_lock: held" in (tmp / "s.rec").read_text(), out
        finally:
            holder.kill()
    rcase("stopped: a process holding the database lock is detected", lock_held)

    def copy_differs(tmp):
        wd, env = host(tmp)
        shutil.copytree(wd / "data", tmp / "copy")
        (tmp / "copy" / "000001.sst").write_bytes(b"different")
        code, _ = record(env, tmp / "s.rec", "--phase", "stopped", "--rollback-copy", str(tmp / "copy"))
        r = dict(l.split(": ", 1) for l in (tmp / "s.rec").read_text().splitlines() if ": " in l)
        return code == 0 and r["data_tree_sha256"] != r["rollback_copy_tree_sha256"], ""
    rcase("stopped: a copy that differs from the data gets a different digest", copy_differs)

    def end_to_end(tmp):
        wd, env = host(tmp)
        new = tmp / "new-sumchain"
        new.write_text(f"#!/bin/sh\necho 'sumchain {RC}'\n")
        new.chmod(0o755)
        code, out = record(env, tmp / "b.rec", "--phase", "before", "--installed", str(new))
        if code:
            return False, out
        import hashlib
        rel = tmp / "release-record.txt"
        rel.write_text(rec(release_commit=RC, x86_64_binary_sha256=hashlib.sha256(new.read_bytes()).hexdigest(),
                           aarch64_binary_sha256=hashlib.sha256(new.read_bytes()).hexdigest()))
        gen = hashlib.sha256((wd / "genesis.json").read_bytes()).hexdigest()
        old = hashlib.sha256((wd / "sumchain").read_bytes()).hexdigest()
        p = subprocess.run([sys.executable, str(CHECKER), "--before", str(tmp / "b.rec"),
                            "--expected-current-sha256", old, "--expected-genesis-sha256", gen,
                            "--release-record", str(rel), "--release-commit", RC], capture_output=True, text=True)
        return p.returncode == 0, p.stdout + p.stderr
    rcase("recorder output feeds the checker end to end", end_to_end)


def main() -> int:
    checker_cases()
    recorder_cases()
    fails = 0
    for name, ok, got in RESULTS:
        print(f"  {'ok  ' if ok else 'FAIL'}  {name}")
        if not ok:
            fails += 1
            print(f"          | {got}")
    print()
    if fails:
        print(f"NATIVE PREFLIGHT BATTERY FAILED: {fails} of {len(RESULTS)}")
        return 1
    print(f"NATIVE PREFLIGHT BATTERY OK: {len(RESULTS)} cases")
    return 0


if __name__ == "__main__":
    sys.exit(main())
