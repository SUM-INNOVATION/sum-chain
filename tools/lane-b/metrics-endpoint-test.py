#!/usr/bin/env python3
"""Every scrape configuration must point at the port /metrics is served on.

The node serves /metrics beside /health and /ready on the [health] port, 8546
(crates/node/src/config.rs; docs/operations/wave1-activation-monitoring.md).
Nothing binds 9090. A scrape of 9090 gets a refused connection, which a
dashboard shows as an empty panel -- the same picture as "nothing refused".

Plain text matching, no YAML library, so it runs on any CI image.

    python3 tools/lane-b/metrics-endpoint-test.py
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HEALTH_PORT = "8546"
failures: list[str] = []


def need(cond: bool, msg: str) -> None:
    if not cond:
        failures.append(msg)


config_rs = (ROOT / "crates/node/src/config.rs").read_text()
need(f'addr: "0.0.0.0:{HEALTH_PORT}"' in config_rs,
     f"crates/node/src/config.rs: the [health] default is no longer 0.0.0.0:{HEALTH_PORT}")

configmap = (ROOT / "deploy/kubernetes/configmap.yaml").read_text()
need(f'addr = "0.0.0.0:{HEALTH_PORT}"' in configmap,
     f"configmap.yaml: [health] addr is not 0.0.0.0:{HEALTH_PORT}")

sts = sorted((ROOT / "deploy/kubernetes").glob("statefulset*.yaml"))
need(len(sts) >= 1, "no validator StatefulSet manifests found")
for f in sts:
    t = f.read_text()
    name = f.name
    ann = re.findall(r'prometheus\.io/port:\s*"(\d+)"', t)
    need(ann == [HEALTH_PORT], f"{name}: prometheus.io/port is {ann}, want ['{HEALTH_PORT}']")
    path = re.findall(r'prometheus\.io/path:\s*"([^"]+)"', t)
    need(path in ([], ["/metrics"]), f"{name}: prometheus.io/path is {path}")
    health = re.findall(r'name:\s*health,?\s*(?:\n\s*)?containerPort:\s*(\d+)', t)
    need(health == [HEALTH_PORT], f"{name}: health containerPort is {health}")
    need("containerPort: 9090" not in t, f"{name}: declares containerPort 9090, which nothing binds")
    for m in re.finditer(r'name:\s*metrics,?\s*(?:\n\s*)?port:\s*\d+,?\s*(?:\n\s*)?targetPort:\s*(\w+)', t):
        need(m.group(1) == "health", f"{name}: Service port 'metrics' targets {m.group(1)!r}, not 'health'")

svc = (ROOT / "deploy/kubernetes/service.yaml").read_text()
targets = re.findall(r'name:\s*metrics\s*\n\s*port:\s*\d+\s*\n\s*targetPort:\s*(\w+)', svc)
need(targets and all(t == "health" for t in targets),
     f"service.yaml: metrics ports target {targets}, want every one 'health'")

prom = (ROOT / "deploy/monitoring/prometheus.yml").read_text()
vt = re.findall(r"'(validator-\d+):(\d+)'", prom)
need(vt and all(p == HEALTH_PORT for _, p in vt), f"prometheus.yml: validator targets {vt}")

compose = (ROOT / "docker-compose.yaml").read_text()
# Node services only: the Prometheus container itself listens on 9090.
for block in re.split(r"\n  (?=[a-z0-9-]+:\n)", compose):
    if block.startswith(("validator", "fullnode")):
        m = re.findall(r'"(\d+):(\d+)"', block)
        bad = [f"{h}:{c}" for h, c in m if c == "9090"]
        need(not bad, f"docker-compose.yaml {block.split(':')[0]}: maps {bad} to a port nothing binds")

if failures:
    for f in failures:
        print("FAIL:", f)
    sys.exit(1)
print(f"METRICS ENDPOINT OK: {len(sts)} StatefulSets, service.yaml, prometheus.yml and "
      f"docker-compose.yaml all scrape the health port {HEALTH_PORT}.")
