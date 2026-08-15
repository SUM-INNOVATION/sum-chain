//! The provenance reader is exercised against crafted `/proc` + `/sys` + cgroup trees:
//! a valid x86 host parses to the exact expected facts, and every flagged field
//! (turbo, clocksource, governor, cpuset, memory limit, cores, cgroup scope) REFUSES
//! when its source is missing or ambiguous — proving there is no hard-coded fallback.

use std::path::{Path, PathBuf};

use b0_pre_host_provenance::{read_host_facts, CpusetState, DvfsState};

struct Tree {
    root: PathBuf,
}
impl Drop for Tree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
impl Tree {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!("b0prov-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        Self { root }
    }
    fn w(&self, rel: &str, contents: &str) {
        let p = self.root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, contents).unwrap();
    }
    fn rm(&self, rel: &str) {
        let _ = std::fs::remove_file(self.root.join(rel));
        let _ = std::fs::remove_dir_all(self.root.join(rel));
    }
    fn root(&self) -> &Path {
        &self.root
    }
}

/// A complete, valid x86 venue host: 2 physical cores / 2 logical, turbo OFF,
/// performance governor, tsc clock, cgroup v2 with a 2-CPU / 16 GiB limit.
fn valid_x86(name: &str) -> Tree {
    let t = Tree::new(name);
    t.w("proc/sys/kernel/ostype", "Linux\n");
    t.w("proc/sys/kernel/osrelease", "6.1.0-venue\n");
    t.w(
        "proc/cpuinfo",
        "processor\t: 0\nvendor_id\t: GenuineIntel\nmodel name\t: Xeon Gold\n\nprocessor\t: 1\nvendor_id\t: GenuineIntel\nmodel name\t: Xeon Gold\n",
    );
    t.w(
        "proc/meminfo",
        "MemTotal:       33554432 kB\nMemFree: 100 kB\n",
    );
    t.w(
        "proc/cmdline",
        "BOOT_IMAGE=/vmlinuz root=/dev/sda1 isolcpus=0,1\n",
    );
    t.w("proc/self/cgroup", "0::/b0-final.slice/measure\n");
    t.w("sys/devices/system/cpu/cpu0/topology/core_id", "0\n");
    t.w(
        "sys/devices/system/cpu/cpu0/topology/physical_package_id",
        "0\n",
    );
    t.w(
        "sys/devices/system/cpu/cpu0/cpufreq/scaling_governor",
        "performance\n",
    );
    t.w("sys/devices/system/cpu/cpu1/topology/core_id", "1\n");
    t.w(
        "sys/devices/system/cpu/cpu1/topology/physical_package_id",
        "0\n",
    );
    t.w(
        "sys/devices/system/cpu/cpu1/cpufreq/scaling_governor",
        "performance\n",
    );
    t.w("sys/devices/system/cpu/intel_pstate/no_turbo", "1\n");
    t.w(
        "sys/devices/system/clocksource/clocksource0/current_clocksource",
        "tsc\n",
    );
    t.w("sys/fs/cgroup/cgroup.controllers", "cpuset memory cpu\n");
    t.w(
        "sys/fs/cgroup/b0-final.slice/measure/cpuset.cpus.effective",
        "0-1\n",
    );
    t.w(
        "sys/fs/cgroup/b0-final.slice/measure/memory.max",
        "17179869184\n",
    );
    t
}

#[test]
fn valid_host_parses_to_exact_facts() {
    let t = valid_x86("valid");
    let f = read_host_facts(t.root()).expect("valid host parses");
    // Deterministic summary facts (probe-chain stat facts inode/mtime are asserted structurally
    // below, not by exact value).
    assert_eq!(f.host_os, "Linux");
    assert_eq!(f.kernel, "6.1.0-venue");
    assert_eq!(f.cpu_vendor, "GenuineIntel");
    assert_eq!(f.cpu_model, "Xeon Gold");
    assert_eq!(f.physical_core_count, 2);
    assert_eq!(f.logical_cpu_count, 2);
    assert_eq!(f.total_ram_bytes, 33554432u64 * 1024);
    assert_eq!(f.configured_cpuset_core_limit, 2);
    assert_eq!(f.cpuset_source_cgroup_path, "/b0-final.slice/measure");
    assert_eq!(f.cpuset_raw, "0-1");
    assert!(!f.cpuset_inherited);
    assert_eq!(f.configured_memory_limit_bytes, 17179869184);
    assert_eq!(
        f.dvfs,
        DvfsState::Observable {
            turbo_enabled: false,
            governor: "performance".into(),
        }
    );
    assert_eq!(f.clock_source, "tsc");
    assert_eq!(f.cgroup_version, 2);
    assert_eq!(f.cgroup_scope_label, "/b0-final.slice/measure");
    // Leaf-observed: the probe chain is exactly one entry (the leaf, order 0) with a stable,
    // readable-nonempty, double-read effective set and captured stat facts.
    assert_eq!(f.cpuset_probe_chain.len(), 1);
    let e = &f.cpuset_probe_chain[0];
    assert_eq!(e.cgroup_path, "/b0-final.slice/measure");
    assert_eq!(e.order, 0);
    assert_eq!(e.first, e.second); // two complete observations must agree
    assert_eq!(e.first.state, CpusetState::ReadableNonempty);
    assert_eq!(e.first.raw.as_deref(), Some("0-1"));
    assert_eq!(e.first.file_type, "regular");
    assert!(!e.first.is_symlink);
    assert_eq!(e.first.size, Some(4)); // "0-1\n"
    assert!(e.first.inode.is_some() && e.first.dev.is_some() && e.first.mtime_secs.is_some());
    assert!(e.first.read_error_class.is_none());
}

// ---- cpuset inheritance (x86 systemd hierarchy: leaf scope lacks the cpuset controller) --------

#[test]
fn inherited_cpuset_from_nearest_ancestor() {
    // The process leaf is a deep tmux scope that does NOT expose cpuset.cpus.effective; the ancestor
    // /b0-final.slice/measure does (valid_x86 wrote "0-1"). The reader must INHERIT it and bind the
    // source, raw, and inherited=true — never refuse, never default to all host CPUs.
    let t = valid_x86("inherited");
    t.w(
        "proc/self/cgroup",
        "0::/b0-final.slice/measure/tmux-spawn.scope\n",
    );
    // the leaf carries memory (isolating the cpuset test) but NOT a cpuset controller file.
    t.w(
        "sys/fs/cgroup/b0-final.slice/measure/tmux-spawn.scope/memory.max",
        "17179869184\n",
    );
    let f = read_host_facts(t.root()).expect("inherited cpuset resolves");
    assert_eq!(f.configured_cpuset_core_limit, 2);
    assert_eq!(f.cpuset_source_cgroup_path, "/b0-final.slice/measure");
    assert_eq!(f.cpuset_raw, "0-1");
    assert!(f.cpuset_inherited);
    assert_eq!(
        f.cgroup_scope_label,
        "/b0-final.slice/measure/tmux-spawn.scope"
    );
    // The canonical probe chain: leaf (order 0, Absent) -> immediate parent (order 1, the selected
    // ReadableNonempty source). It stops AT the source: no entry after it, no skipped level.
    assert_eq!(f.cpuset_probe_chain.len(), 2);
    let leaf = &f.cpuset_probe_chain[0];
    assert_eq!(leaf.order, 0);
    assert_eq!(leaf.cgroup_path, "/b0-final.slice/measure/tmux-spawn.scope");
    assert_eq!(leaf.first.state, CpusetState::Absent);
    assert_eq!(leaf.first.file_type, "absent");
    assert_eq!(leaf.first, leaf.second);
    let src = &f.cpuset_probe_chain[1];
    assert_eq!(src.order, 1);
    assert_eq!(src.cgroup_path, "/b0-final.slice/measure");
    assert_eq!(src.first.state, CpusetState::ReadableNonempty);
    assert_eq!(src.first.raw.as_deref(), Some("0-1"));
    assert_eq!(src.first, src.second);
}

#[test]
fn leaf_observed_takes_precedence_over_ancestor() {
    // The leaf exposes cpuset -> leaf-observed (inherited=false), even though an ancestor also does.
    let t = valid_x86("leaf-wins");
    t.w(
        "proc/self/cgroup",
        "0::/b0-final.slice/measure/tmux.scope\n",
    );
    t.w(
        "sys/fs/cgroup/b0-final.slice/measure/tmux.scope/cpuset.cpus.effective",
        "3\n",
    );
    t.w(
        "sys/fs/cgroup/b0-final.slice/measure/tmux.scope/memory.max",
        "17179869184\n",
    );
    let f = read_host_facts(t.root()).expect("leaf-observed resolves");
    assert_eq!(f.configured_cpuset_core_limit, 1);
    assert_eq!(
        f.cpuset_source_cgroup_path,
        "/b0-final.slice/measure/tmux.scope"
    );
    assert_eq!(f.cpuset_raw, "3");
    assert!(!f.cpuset_inherited);
}

#[test]
fn no_cpuset_anywhere_in_chain_refuses_never_defaults_to_all() {
    // Neither the leaf nor any ancestor exposes cpuset -> REFUSE (never fall back to logical=2).
    let t = valid_x86("no-cpuset");
    t.w(
        "proc/self/cgroup",
        "0::/b0-final.slice/measure/tmux.scope\n",
    );
    t.rm("sys/fs/cgroup/b0-final.slice/measure/cpuset.cpus.effective");
    t.w(
        "sys/fs/cgroup/b0-final.slice/measure/tmux.scope/memory.max",
        "17179869184\n",
    );
    let e = read_host_facts(t.root()).unwrap_err();
    assert!(e.contains("cpuset"), "{e}");
}

#[test]
fn malformed_ancestor_cpuset_refuses() {
    let t = valid_x86("malformed");
    t.w(
        "proc/self/cgroup",
        "0::/b0-final.slice/measure/tmux.scope\n",
    );
    t.w(
        "sys/fs/cgroup/b0-final.slice/measure/cpuset.cpus.effective",
        "not-a-cpu-list\n",
    );
    t.w(
        "sys/fs/cgroup/b0-final.slice/measure/tmux.scope/memory.max",
        "17179869184\n",
    );
    assert!(read_host_facts(t.root()).is_err());
}

#[test]
fn symlink_cpuset_source_refuses() {
    let t = valid_x86("symlink");
    t.rm("sys/fs/cgroup/b0-final.slice/measure/cpuset.cpus.effective");
    // Replace the leaf effective-cpuset with a symlink -> refused (no redirection out of the tree).
    let link = t
        .root()
        .join("sys/fs/cgroup/b0-final.slice/measure/cpuset.cpus.effective");
    std::os::unix::fs::symlink("/etc/hostname", &link).unwrap();
    let e = read_host_facts(t.root()).unwrap_err();
    assert!(e.contains("symlink"), "{e}");
}

#[test]
fn nonregular_cpuset_fails_immediately_and_does_not_skip_to_farther_valid() {
    // Rule 1: an ambiguous (non-regular) cpuset at a NEARER cgroup fails immediately — the reader
    // must NOT skip it to reach a valid farther ancestor.
    let t = valid_x86("nonreg");
    t.w(
        "proc/self/cgroup",
        "0::/b0-final.slice/measure/tmux.scope\n",
    );
    t.w(
        "sys/fs/cgroup/b0-final.slice/measure/tmux.scope/memory.max",
        "17179869184\n",
    );
    // leaf tmux.scope: no cpuset (absent). middle /b0-final.slice/measure: a DIRECTORY at the cpuset
    // path (non-regular/ambiguous). farther /b0-final.slice: a VALID cpuset that must NOT be reached.
    t.rm("sys/fs/cgroup/b0-final.slice/measure/cpuset.cpus.effective");
    std::fs::create_dir_all(
        t.root()
            .join("sys/fs/cgroup/b0-final.slice/measure/cpuset.cpus.effective"),
    )
    .unwrap();
    t.w("sys/fs/cgroup/b0-final.slice/cpuset.cpus.effective", "0\n");
    let e = read_host_facts(t.root()).unwrap_err();
    assert!(
        e.contains("not a regular file") || e.contains("ambiguous"),
        "{e}"
    );
}

#[test]
fn noncanonical_cgroup_scope_refuses() {
    let t = valid_x86("noncanon");
    t.w("proc/self/cgroup", "0::/b0-final.slice/../measure\n");
    let e = read_host_facts(t.root()).unwrap_err();
    assert!(e.contains("non-canonical") || e.contains("ancestor"), "{e}");
}

#[test]
fn turbo_enabled_is_read_not_assumed() {
    let t = valid_x86("turbo-on");
    t.w("sys/devices/system/cpu/intel_pstate/no_turbo", "0\n");
    match read_host_facts(t.root()).unwrap().dvfs {
        DvfsState::Observable { turbo_enabled, .. } => assert!(turbo_enabled),
        other => panic!("expected Observable, got {other:?}"),
    }
}

#[test]
fn undeterminable_turbo_refuses() {
    let t = valid_x86("turbo-none");
    t.rm("sys/devices/system/cpu/intel_pstate");
    let e = read_host_facts(t.root()).unwrap_err();
    assert!(e.contains("turbo"), "{e}");
}

#[test]
fn nonuniform_governor_refuses() {
    let t = valid_x86("gov-mixed");
    t.w(
        "sys/devices/system/cpu/cpu1/cpufreq/scaling_governor",
        "powersave\n",
    );
    let e = read_host_facts(t.root()).unwrap_err();
    assert!(e.contains("governor"), "{e}");
}

#[test]
fn missing_clocksource_refuses() {
    let t = valid_x86("clk-none");
    t.rm("sys/devices/system/clocksource/clocksource0/current_clocksource");
    assert!(read_host_facts(t.root()).is_err());
}

#[test]
fn missing_cpuset_refuses() {
    let t = valid_x86("cpuset-none");
    t.rm("sys/fs/cgroup/b0-final.slice/measure/cpuset.cpus.effective");
    assert!(read_host_facts(t.root()).is_err());
}

#[test]
fn missing_memory_limit_refuses() {
    let t = valid_x86("mem-none");
    t.rm("sys/fs/cgroup/b0-final.slice/measure/memory.max");
    assert!(read_host_facts(t.root()).is_err());
}

#[test]
fn memory_max_literal_resolves_to_ram() {
    let t = valid_x86("mem-max");
    t.w("sys/fs/cgroup/b0-final.slice/measure/memory.max", "max\n");
    assert_eq!(
        read_host_facts(t.root())
            .unwrap()
            .configured_memory_limit_bytes,
        33554432u64 * 1024
    );
}

#[test]
fn missing_topology_refuses_never_guesses_cores() {
    let t = valid_x86("topo-none");
    t.rm("sys/devices/system/cpu/cpu1/topology/core_id");
    assert!(read_host_facts(t.root()).is_err());
}

#[test]
fn cgroup_scope_label_is_read_from_proc_not_fixed() {
    let t = valid_x86("scope");
    t.w("proc/self/cgroup", "0::/custom.slice/run-42.scope\n");
    // the scope dir must exist for the cpuset/memory reads
    t.w(
        "sys/fs/cgroup/custom.slice/run-42.scope/cpuset.cpus.effective",
        "0-1\n",
    );
    t.w(
        "sys/fs/cgroup/custom.slice/run-42.scope/memory.max",
        "1073741824\n",
    );
    let f = read_host_facts(t.root()).unwrap();
    assert_eq!(f.cgroup_scope_label, "/custom.slice/run-42.scope");
    assert_eq!(f.configured_memory_limit_bytes, 1073741824);
}
