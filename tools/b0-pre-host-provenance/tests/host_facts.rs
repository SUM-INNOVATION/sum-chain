//! The provenance reader is exercised against crafted `/proc` + `/sys` + cgroup trees:
//! a valid x86 host parses to the exact expected facts, and every flagged field
//! (turbo, clocksource, governor, cpuset, memory limit, cores, cgroup scope) REFUSES
//! when its source is missing or ambiguous — proving there is no hard-coded fallback.

use std::path::{Path, PathBuf};

use b0_pre_host_provenance::{read_host_facts, HostFacts};

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
    assert_eq!(
        f,
        HostFacts {
            host_os: "Linux".into(),
            kernel: "6.1.0-venue".into(),
            cpu_vendor: "GenuineIntel".into(),
            cpu_model: "Xeon Gold".into(),
            physical_core_count: 2,
            logical_cpu_count: 2,
            total_ram_bytes: 33554432u64 * 1024,
            configured_cpuset_core_limit: 2,
            configured_memory_limit_bytes: 17179869184,
            governor: "performance".into(),
            turbo_enabled: false,
            clock_source: "tsc".into(),
            cgroup_version: 2,
            cgroup_scope_label: "/b0-final.slice/measure".into(),
        }
    );
}

#[test]
fn turbo_enabled_is_read_not_assumed() {
    let t = valid_x86("turbo-on");
    t.w("sys/devices/system/cpu/intel_pstate/no_turbo", "0\n");
    assert!(read_host_facts(t.root()).unwrap().turbo_enabled);
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
