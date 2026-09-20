//! The Kubernetes QoS class the four validator StatefulSets actually get.
//!
//! # The claim this file corrects, and why it is not a documentation nit
//!
//! `docs/operations/validator-memory-floor.md` and all four StatefulSets said
//! that setting `requests.memory` equal to `limits.memory` gives the pod
//! **Guaranteed** QoS. It does not. Kubernetes assigns `Guaranteed` only when,
//! for EVERY container in the pod, BOTH memory AND cpu have a limit and a
//! request and the two are equal. These manifests set `requests.cpu: 500m`
//! against `limits.cpu: 2000m`, so every one of these pods is **Burstable**.
//!
//! That matters because the 4 GiB memory floor is what
//! `MAX_BLOCK_WRITE_SET_BYTES` (256 MiB) is derived from. An operator who
//! believes the pod is Guaranteed believes the floor is reserved for a reason
//! that is not the real reason, and would "fix" a future eviction by looking
//! at the wrong field.
//!
//! **The correction is to the CLAIM, not to the CPU numbers.** Raising
//! `requests.cpu` to 2000m to obtain the label would reserve four times the
//! scheduler CPU on every validator node and can make the pods unschedulable
//! on small nodes. The 4 GiB memory request and limit are preserved exactly.
//!
//! # The four things this file keeps apart
//!
//! | thing | field | what it does | QoS-dependent? |
//! |---|---|---|---|
//! | scheduler reservation | `requests` | reserves node allocatable; the pod is only placed where 4 GiB is free | **no** |
//! | cgroup limit | `limits` | `memory.max`; exceeding it is a container OOM-kill and restart | **no** |
//! | QoS classification | derived | the pod-level label; **Burstable** here | — |
//! | kubelet eviction ranking | derived from usage vs `requests` | a pod whose usage does not exceed its requests is in the last-evicted tier | **not by class alone** |
//!
//! The last row is the one worth stating precisely, because it is the reason
//! Burstable is acceptable here: kubelet node-pressure eviction does not evict
//! a pod whose usage does not exceed its requests, and ranks
//! Guaranteed pods together with Burstable pods that are under their requests
//! last. With `requests.memory == limits.memory`, this container cannot exceed
//! its memory request without having already exceeded its identical memory
//! limit — at which point the cgroup OOM killer has acted, which is a
//! container restart and not a kubelet eviction. So the 4 GiB is protected on
//! the eviction path whether or not the pod-level label says Guaranteed.
//!
//! What Burstable does cost is the kernel-OOM tier: the kubelet writes
//! `oom_score_adj = -997` for a Guaranteed container and, for a Burstable one,
//! `1000 - 1000 * memoryRequest / machineCapacity` clamped into `[2, 999]`.
//! Under a SYSTEM-level OOM — as opposed to a kubelet eviction — this
//! container is therefore a more attractive victim than a Guaranteed one would
//! be. That residual is recorded in the operations page rather than papered
//! over; it is not closed by any field these manifests could set without
//! changing the CPU reservation.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const MANIFESTS: [&str; 4] = [
    "deploy/kubernetes/statefulset.yaml",
    "deploy/kubernetes/statefulset-validator-1.yaml",
    "deploy/kubernetes/statefulset-validator-2.yaml",
    "deploy/kubernetes/statefulset-validator-3.yaml",
];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/state -> crates -> repository root")
        .to_path_buf()
}

/// One container's resource declaration, as the manifest states it.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Resources {
    request_cpu: Option<String>,
    limit_cpu: Option<String>,
    request_memory: Option<String>,
    limit_memory: Option<String>,
}

/// The Kubernetes QoS class a pod is assigned.
#[derive(Debug, PartialEq, Eq)]
enum Qos {
    Guaranteed,
    Burstable,
    BestEffort,
}

impl Resources {
    /// Does this container satisfy the per-container half of `Guaranteed`?
    ///
    /// Both resources, both sides, both equal. This is the rule as Kubernetes
    /// states it, spelled out rather than summarised, because the summary
    /// ("equal request and limit") is exactly the summary that produced the
    /// wrong claim.
    fn meets_guaranteed(&self) -> bool {
        let both_equal = |req: &Option<String>, lim: &Option<String>| match (req, lim) {
            (Some(r), Some(l)) => r == l && !r.is_empty() && r != "0",
            _ => false,
        };
        both_equal(&self.request_memory, &self.limit_memory)
            && both_equal(&self.request_cpu, &self.limit_cpu)
    }

    fn declares_anything(&self) -> bool {
        self.request_cpu.is_some()
            || self.limit_cpu.is_some()
            || self.request_memory.is_some()
            || self.limit_memory.is_some()
    }
}

/// The pod's QoS class, from every container in it.
///
/// Init containers count too, which is why they are collected alongside the
/// ordinary ones rather than skipped.
fn qos_of(containers: &BTreeMap<String, Resources>) -> Qos {
    assert!(!containers.is_empty(), "a pod with no containers");
    if containers.values().all(Resources::meets_guaranteed) {
        Qos::Guaranteed
    } else if containers.values().any(Resources::declares_anything) {
        Qos::Burstable
    } else {
        Qos::BestEffort
    }
}

/// Rewrite `key: { a: "x", b: "y" }` flow mappings into block form, so one
/// indentation-aware walk handles both spellings these manifests use.
fn expand_flow_mappings(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for line in text.lines() {
        let trimmed = line.trim_start();
        let indent = line.len() - trimmed.len();
        // `key:` then any run of spaces then `{ … }`. The manifests align the
        // braces into a column, so the separator is not a fixed string.
        let flow = trimmed.find(':').and_then(|c| {
            let after = &trimmed[c + 1..];
            after
                .find('{')
                .filter(|&b| after[..b].chars().all(|ch| ch == ' '))
                .map(|b| (c, c + 1 + b))
        });
        match (flow, trimmed.ends_with('}')) {
            (Some((at, brace)), true) => {
                let key = &trimmed[..at];
                let inner = &trimmed[brace + 1..trimmed.len() - 1];
                out.push_str(&format!("{}{}:\n", " ".repeat(indent), key));
                for pair in inner.split(',') {
                    let pair = pair.trim();
                    if pair.is_empty() {
                        continue;
                    }
                    out.push_str(&format!("{}{}\n", " ".repeat(indent + 2), pair));
                }
            }
            _ => {
                out.push_str(line);
                out.push('\n');
            }
        }
    }
    out
}

/// Every container in the pod template, with the resources it declares.
///
/// Deliberately a small hand-rolled walk rather than a YAML dependency: this
/// crate takes no YAML dependency, and the shape being read is four files of
/// known structure. It asserts the structure it assumes (see the callers)
/// rather than silently returning an empty map when the shape changes.
fn containers_of(manifest_text: &str) -> BTreeMap<String, Resources> {
    let text = expand_flow_mappings(manifest_text);
    let lines: Vec<&str> = text.lines().collect();
    let indent_of = |l: &str| l.len() - l.trim_start().len();

    let mut found: BTreeMap<String, Resources> = BTreeMap::new();
    let mut i = 0usize;
    while i < lines.len() {
        let trimmed = lines[i].trim();
        if trimmed != "containers:" && trimmed != "initContainers:" {
            i += 1;
            continue;
        }
        let list_indent = indent_of(lines[i]);
        let kind = trimmed.trim_end_matches(':').to_string();
        i += 1;
        // Walk the list items until the indentation returns to the key's level.
        //
        // Only a `- name:` at the LIST ITEM's own indentation starts a new
        // container. Deeper ones are `env:` entries, `ports:` entries and
        // volume mounts, which also spell themselves `- name: …` and which an
        // indentation-blind scan would count as containers.
        let mut current: Option<String> = None;
        let mut item_indent: Option<usize> = None;
        while i < lines.len() {
            let line = lines[i];
            if line.trim().is_empty() {
                i += 1;
                continue;
            }
            if indent_of(line) <= list_indent {
                break;
            }
            let t = line.trim();
            let is_item = t.starts_with("- ") && item_indent.is_none_or(|w| indent_of(line) == w);
            if is_item {
                item_indent = Some(indent_of(line));
            }
            if let (true, Some(name)) = (is_item, t.strip_prefix("- name: ")) {
                current = Some(format!("{kind}/{}", name.trim()));
                found.entry(current.clone().unwrap()).or_default();
            } else if t == "resources:" && current.is_some() {
                let res_indent = indent_of(line);
                let key = current
                    .clone()
                    .expect("a resources: block outside any container");
                let mut section: Option<&'static str> = None;
                i += 1;
                while i < lines.len() {
                    let rl = lines[i];
                    if rl.trim().is_empty() {
                        i += 1;
                        continue;
                    }
                    if indent_of(rl) <= res_indent {
                        break;
                    }
                    let rt = rl.trim();
                    match rt {
                        "requests:" => section = Some("requests"),
                        "limits:" => section = Some("limits"),
                        _ => {
                            let (field, value) = match rt.split_once(": ") {
                                Some((f, v)) => (f.trim(), v.trim().trim_matches('"').to_string()),
                                None => {
                                    i += 1;
                                    continue;
                                }
                            };
                            let e = found.entry(key.clone()).or_default();
                            match (section, field) {
                                (Some("requests"), "cpu") => e.request_cpu = Some(value),
                                (Some("requests"), "memory") => e.request_memory = Some(value),
                                (Some("limits"), "cpu") => e.limit_cpu = Some(value),
                                (Some("limits"), "memory") => e.limit_memory = Some(value),
                                _ => {}
                            }
                        }
                    }
                    i += 1;
                }
                continue;
            }
            i += 1;
        }
    }
    found
}

fn manifest_text(manifest: &str) -> String {
    std::fs::read_to_string(repo_root().join(manifest))
        .unwrap_or_else(|e| panic!("{manifest} must be readable: {e}"))
}

// ── the claim ───────────────────────────────────────────────────────────────

/// **Every validator pod is Burstable, and the document must say so.**
///
/// Derived from the manifests by the rule Kubernetes applies, not asserted.
/// If someone later equalises the CPU request and limit, this fails and the
/// document has to be corrected in the other direction — which is the right
/// outcome, because the eviction paragraph would then be wrong.
#[test]
fn every_validator_pod_is_burstable_because_cpu_request_and_limit_differ() {
    for manifest in MANIFESTS {
        let containers = containers_of(&manifest_text(manifest));
        assert!(
            !containers.is_empty(),
            "{manifest}: no containers were parsed — the manifest shape changed \
             and this check has stopped checking anything"
        );
        for (name, r) in &containers {
            assert!(
                r.request_cpu.is_some() && r.limit_cpu.is_some(),
                "{manifest}/{name}: cpu request and limit must both be stated for \
                 the QoS rule to be decidable from this file"
            );
        }
        assert_eq!(
            qos_of(&containers),
            Qos::Burstable,
            "{manifest}: {containers:#?}\n\
             Guaranteed requires request == limit for BOTH cpu and memory in \
             EVERY container. If this now says Guaranteed, the CPU reservation \
             was raised — re-read docs/operations/validator-memory-floor.md, \
             whose eviction paragraph is written for a Burstable pod."
        );
    }
}

/// **The 4 GiB memory reservation is preserved, on both sides, in every
/// container.** This is the number `MAX_BLOCK_WRITE_SET_BYTES` divides.
#[test]
fn the_four_gib_memory_request_and_limit_are_equal_and_unchanged() {
    for manifest in MANIFESTS {
        let containers = containers_of(&manifest_text(manifest));
        for (name, r) in &containers {
            assert_eq!(
                r.request_memory.as_deref(),
                Some("4Gi"),
                "{manifest}/{name}: the memory REQUEST is what the scheduler \
                 reserves and what kubelet eviction ranks against"
            );
            assert_eq!(
                r.limit_memory.as_deref(),
                Some("4Gi"),
                "{manifest}/{name}: the memory LIMIT is the cgroup ceiling the \
                 write-set derivation assumes"
            );
        }
    }
}

/// Exactly one container per pod, and no init containers.
///
/// The QoS rule quantifies over EVERY container including init containers, so
/// "the pod is Burstable" is only a complete statement while the set of
/// containers is known. A sidecar added later with no resources at all would
/// not change the class here — but one added with equal cpu and memory could,
/// and either way the eviction reasoning would need re-reading.
#[test]
fn each_validator_pod_has_exactly_one_container_and_no_init_containers() {
    for manifest in MANIFESTS {
        let text = manifest_text(manifest);
        assert!(
            !text.contains("initContainers:"),
            "{manifest}: an init container appeared; the QoS rule quantifies \
             over init containers too"
        );
        let containers = containers_of(&text);
        assert_eq!(
            containers.keys().collect::<Vec<_>>(),
            vec![&"containers/sumchain".to_string()],
            "{manifest}: the container set changed"
        );
    }
}

/// The documentation and the manifests state the class the manifests produce.
///
/// The correction is only real if the prose moved with it. This is the guard
/// against the document drifting back to the comfortable claim.
///
/// Phrases rather than a bare search for "Guaranteed": the corrected text has
/// to be ABLE to name the class in order to say the pods are not in it, and to
/// state the rule Guaranteed actually has. What is refused is the ASSERTION.
#[test]
fn no_shipped_text_claims_these_pods_are_guaranteed() {
    /// Whitespace-normalised, lower-cased assertions that these pods are
    /// Guaranteed. Each of these was, or is one edit away from, the claim this
    /// pass corrected.
    const FORBIDDEN: &[&str] = &[
        "is guaranteed qos",
        "is guaranteed qos for memory",
        "makes the pod guaranteed",
        "makes it guaranteed",
        "pod is guaranteed",
        "pods are guaranteed",
        "qos class is guaranteed",
        "equal request and limit is guaranteed",
        "request and limit is guaranteed",
        "gets guaranteed",
        "give guaranteed qos",
        "gives guaranteed qos",
    ];

    let root = repo_root();
    let docs = [
        "docs/operations/validator-memory-floor.md",
        "docs/b0-pre/protocol/VALIDATOR-MEMORY-FLOOR-RECONCILIATION.md",
    ];
    for path in docs.iter().chain(MANIFESTS.iter()) {
        let text = std::fs::read_to_string(root.join(path))
            .unwrap_or_else(|e| panic!("{path} must be readable: {e}"));
        let flat = text
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_lowercase()
            .replace(['*', '`', '_'], "");
        for phrase in FORBIDDEN {
            assert!(
                !flat.contains(phrase),
                "{path}: contains {phrase:?}. These pods are Burstable — \
                 cpu 500m against 2000m — and the derivation in this file's \
                 sibling test says so on every run."
            );
        }
        if flat.contains("guaranteed") {
            assert!(
                flat.contains("burstable"),
                "{path}: names the Guaranteed class without naming the one \
                 these pods are actually in"
            );
        }
    }
    // And the class is named where an operator will look for it.
    let page = std::fs::read_to_string(root.join(docs[0])).expect("the operations page");
    assert!(
        page.contains("Burstable"),
        "the operations page must state the class the manifests produce"
    );
}
