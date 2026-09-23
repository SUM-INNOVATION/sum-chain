# Monitoring the Wave 1 activation

A runnable procedure, not a description of one. Everything below is a command,
a query, or a file an operator applies.

> **What changed, and why this page exists now.** Twenty-two of the twenty-four
> Wave 1 gates are REFUSAL ONLY: a transaction that used to succeed produces a
> failed receipt instead. The decision packet said the same sentence about each
> of them — *"No counter exists … so this is per-transaction inspection"* —
> because `sumchain_tx_execution_errors_total` was declared and never
> incremented.
>
> **It is incremented now**, at the single receipt-construction site in
> `BlockExecutor::execute_block`, and it carries two labels: `subsystem` and
> `code`. That turns "did anything start being refused, and by which
> subsystem" from a walk over transaction hashes into one query.
>
> **This telemetry must be in the binary deployed at STAGE 1, before any height
> is set.** A counter that arrives with the activation cannot establish the
> baseline the activation is judged against.

---

## 0. The one metric, and its exact shape

```
# HELP sumchain_tx_execution_errors_total Failed transaction receipts, by subsystem and status code
# TYPE sumchain_tx_execution_errors_total counter
sumchain_tx_execution_errors_total{subsystem="healthcare",code="14"} 0
sumchain_tx_execution_errors_total{subsystem="docclass",code="8"} 0
…
```

* Endpoint: `GET /metrics` on the **health port, 8546** -- served by
  `crates/rpc/src/health.rs` beside `/health` and `/ready`, bound to
  `[health] addr` (default `0.0.0.0:8546`). **Not 9090.** The manifests declare
  a container port 9090 and annotate `prometheus.io/port: "9090"`, and nothing
  in the code binds that port: anything scraping 9090 -- Prometheus through that
  annotation, or an operator following an older copy of this page -- gets a
  refused connection, not a zero. Check that the scrape actually returns a
  body before trusting any silence from it.
* **Exactly two labels, and they are bounded.** Both values are `&'static str`
  drawn from a closed table in `crates/primitives/src/tx_error_metrics.rs`; the
  counters are a fixed-length array indexed by position in that table, so there
  is no insert path and the series set cannot grow at runtime. A label taken
  from the transaction — a sender, a hash, a formatted reason — would let one
  funded account allocate registry memory in every node that scrapes itself.
  Pinned by `the_counter_carries_exactly_two_labels_named_subsystem_and_code`
  and `no_label_value_can_come_from_a_transaction`.
* **Every series is emitted on every scrape, zeroes included.** That is
  deliberate: after opening a gate you must be able to tell *"the gate refused
  nothing"* from *"this binary does not have the counter"*, and an absent
  series cannot make that distinction.
* A `code` is the decimal `TxStatus::Failed(n)`. The reason text for each is
  `TxStatus::description()` in `crates/primitives/src/receipt.rs`.

### The nine Wave 1 subsystems and their codes

| subsystem | `code` | Wave 1 gates that refuse through it |
|---|---|---|
| `nft` | `2` | R15, R33, R40, R13 |
| `docclass` | `8` | R4, R23, R25, R36, R37, R38, R13 |
| `tax` | `9` | R10, R31, R13 |
| `agreement` | `11` | R29, R39, R13 |
| `legal` | `12` | R6, R13 |
| `property` | `13` | R9, R32, R34, R39, R13 |
| `healthcare` | `14` | R5, R30, R39, R13 |
| `employment` | `15` | R8, R13 |
| `finance` | `16` | R7, R31, R13 |

Every row is demonstrated, not asserted: `crates/state/tests/wave1_execution_error_signal.rs`
opens the gate, publishes a real block with the refused shape in it, and
requires that subsystem's series to advance by exactly one while every other
series stays still.

---

## 1. Before the height — establish the baseline

Run on every validator, and keep the output. A rate that looks alarming after
the height is only alarming relative to what it was before.

```bash
tools/lane-b/wave1-monitor.sh baseline http://validator-1:8546 > baseline-v1.txt
tools/lane-b/wave1-monitor.sh baseline http://validator-2:8546 > baseline-v2.txt
```

One line per validator. The live network has **two** (`sum_getValidators`,
and the proposer alternates strictly between two keys); an earlier copy of this
page listed three.

**The counter is per-process and starts at zero on every restart.** A raw total
means "refusals since this process started", so it differs between two healthy
validators that started at different times, and it drops to zero under any one
of them when it restarts. That is why each baseline records the wall-clock
time, the node's uptime and the block height, and why `delta` and `agree`
compare DELTAS over a window instead of totals:

```bash
# later: what has moved on one validator since its baseline
tools/lane-b/wave1-monitor.sh delta http://validator-1:8546 baseline-v1.txt

# do the validators refuse the same things over the same blocks?
tools/lane-b/wave1-monitor.sh agree baseline-v1.txt baseline-v2.txt
```

Both check the window for a restart first -- the process start time (wall
clock minus uptime) moving forward, or any series going down -- and exit **3,
INCONCLUSIVE** if there was one: the window cannot be measured, so take new
baselines. `delta` never reports "nothing moved" across a restart; before this
was fixed it did, hiding every refusal since the restart. `agree` reports
DISAGREE (exit 1) only when every node covered the identical block range with
no restart and the refusals still differ -- the one case that really is a fork.
Nodes a block apart are INCONCLUSIVE, not a fork.

The script also asserts the metric family is present and correctly shaped. **If
it reports `MISSING` the deployed binary predates this telemetry and stage 1 is
not complete** — do not proceed to stage 2.

---

## 2. Alert rules — apply these before the height

`deploy/monitoring/prometheus.yml` ships `rule_files: []`. Add
`wave1-activation.rules.yml` beside it and reference it:

```yaml
# deploy/monitoring/wave1-activation.rules.yml
groups:
  - name: wave1-activation
    rules:
      # The gate fired at all. Expected to go non-zero shortly after the
      # height for at least one subsystem; a flat zero across all nine an hour
      # after the height means either no traffic hit the refused shapes or the
      # gate is not open on this node.
      - record: wave1:refusals:rate5m
        expr: sum by (subsystem) (rate(sumchain_tx_execution_errors_total[5m]))

      # The whole point of the two labels.
      - record: wave1:refusals:rate5m_by_code
        expr: sum by (subsystem, code) (rate(sumchain_tx_execution_errors_total[5m]))

      # THE MISBEHAVING SIGNAL. A refusal rate that keeps climbing after the
      # first hour is legitimate traffic being refused, not the backlog of
      # un-upgraded clients draining.
      - alert: Wave1RefusalRateStillClimbing
        expr: |
          wave1:refusals:rate5m > 0
          and
          wave1:refusals:rate5m > 1.5 * (wave1:refusals:rate5m offset 1h)
        for: 30m
        labels: { severity: page }
        annotations:
          summary: "{{ $labels.subsystem }} refusals rising 90m after activation"
          runbook: docs/operations/wave1-activation-monitoring.md#4-reading-the-signal

      # THE NODES DISAGREE. Two validators executing the same blocks must
      # produce the same refusals. A divergence here is a mixed-binary or
      # mixed-genesis condition and is a fork in progress.
      - alert: Wave1RefusalsDisagreeAcrossValidators
        expr: |
          stddev by (subsystem, code) (sumchain_tx_execution_errors_total) > 0
        for: 10m
        labels: { severity: page }
        annotations:
          summary: "validators disagree on {{ $labels.subsystem }}/{{ $labels.code }} refusal counts"
          runbook: docs/operations/activation-rollout-evidence.md#4-the-abort-rule

      # A code with no allocated series. Not an emergency, but it means a
      # refusal exists that telemetry cannot name.
      - alert: Wave1UnattributedRefusals
        expr: rate(sumchain_tx_execution_errors_total{subsystem="unknown"}[15m]) > 0
        for: 15m
        labels: { severity: warning }
        annotations:
          summary: "refusals landing on the unattributed series"

      # LIVENESS, which is what Wave 3 (R1) is really about but which must be
      # watched through every wave.
      - alert: BlockProductionStopped
        expr: rate(sumchain_blocks_produced_total[10m]) == 0
        for: 10m
        labels: { severity: page }
        annotations: { summary: "no blocks produced in 10 minutes" }
```

Then:

```diff
 # deploy/monitoring/prometheus.yml
-rule_files: []
+rule_files:
+  - wave1-activation.rules.yml
```

```bash
promtool check rules deploy/monitoring/wave1-activation.rules.yml
promtool check config deploy/monitoring/prometheus.yml
```

---

## 3. Dashboard — the four panels that matter

`deploy/monitoring/grafana/` already provisions a datasource and a dashboard
folder. One dashboard, four panels, in this order:

| # | panel | query | what it answers |
|---|---|---|---|
| 1 | *Refusals by subsystem* (stacked area) | `sum by (subsystem) (rate(sumchain_tx_execution_errors_total[5m]))` | which subsystem started refusing |
| 2 | *Refusals by code* (table, sorted desc) | `topk(20, sum by (subsystem, code) (increase(sumchain_tx_execution_errors_total[1h])))` | which rule inside it |
| 3 | *Cross-validator agreement* (one series per instance) | `sum by (instance) (sumchain_tx_execution_errors_total)` | are the nodes executing the same chain |
| 4 | *Liveness* | `rate(sumchain_blocks_produced_total[5m])` and `sumchain_block_height` | is the chain still moving |

Panel 3 is the one an operator should look at first after the height. Panels 1
and 2 tell you what the gate is doing; panel 3 tells you whether the nodes
agree that it is doing it, and disagreement there outranks everything else.

---

## 4. Reading the signal

For each of the nine subsystems, after the Wave 1 height:

| observation | reading |
|---|---|
| series flat at its baseline | either no traffic submitted a refused shape, or **this node's gate is not open** — check `chain_getActivationStatus` `gates[].active` before concluding the former |
| series steps up, then the rate decays over the first hours | **working.** Un-upgraded clients and strangers being refused, and the traffic draining as they are fixed |
| rate still climbing 90 minutes in | **investigate.** Legitimate senders are being refused. `Wave1RefusalRateStillClimbing` pages on this |
| one validator's count differs from another's | **stop.** The nodes are not executing the same chain. Go to the abort rule |
| refusals on `subsystem="unknown"` | a `Failed(n)` with no allocated series. Not urgent, but find the code and allocate it |

**The counter tells you a subsystem refused something. It does not tell you
whether the refused sender had legitimate standing.** For the refusal-only
gates those are the same event in the receipt — that is a property of the
gates, not of the telemetry — so any sustained non-zero rate needs one
`sum_getReceipt` on a sample transaction to see which. The counter reduces that
from "walk every transaction" to "sample the subsystem the counter named".

---

## 5. Where the counter is the ONLY signal

M6 in the decision packet is "read a known row over RPC before and after the
height". For several Wave 1 families **there is no RPC read method at all**, so
M6 does not exist for them and the counter is the entire signal. Verified
against `crates/rpc/src/api.rs` in this tree:

| family | RPC read methods | M6 available? |
|---|---|---|
| **Healthcare consents** | none | **NO.** The Healthcare surface is `healthcare_getInstitutionalProvider` and `healthcare_getActiveInstitutionalProviders` — an explicit allowlist of institutional provider types, carrying "no memberships, consents, prescriptions, proofs, events, or member/patient/subject data" (`crates/rpc/src/api.rs:1529-1533`). A consent row cannot be read over RPC before or after the height. Affects **R30, R5** |
| **Property proofs** | none | **NO.** Affects **R32** |
| **Property title events** | none | **NO** |
| **Property encumbrances** | none | **NO** |
| **Property coverage** | none | **NO** |
| **Property claims** | none | **NO** |
| **Property assets** | `property_getAsset`, `property_getActiveAssets`, `property_getAssetsByJurisdiction` | yes — and it is the **only** Property family with a reader. Five of the six Property record families (`PROPERTY_TITLE_EVENTS`, `PROPERTY_ENCUMBRANCES`, `PROPERTY_COVERAGE`, `PROPERTY_CLAIMS`, `PROPERTY_PROOFS`) have none |
| **Agreements, parties, signatures** | none | **NO.** The Agreement surface is `agreement_getExecutorLink`, `agreement_getExecutorLinksByAgreement`, `agreement_getExecutorLinksByExecutor`, `agreement_getActiveExecutorLinks` — executor links only. There is no read method for an agreement, a party or a signature. Affects **R29, R39** |

For those rows, after the height an operator has: **M1** (`gates[].active`,
confirming the gate fired), **this counter** (confirming the subsystem started
refusing, and at what rate), and **M4** (`sum_getReceipt` on a sample hash,
confirming which rule). There is no way to read the protected row itself and
compare it across the height, and nothing in this release changes that.

---

## 5b. What the counter does NOT count: proposal screening

`sumchain_tx_execution_errors_total` counts refusals that produced a COMMITTED
RECEIPT. Refusals seen during proposal screening are deliberately excluded --
the `record` call sits behind `screening.is_none()` at the receipt-construction
seam.

**Why, and what it means for reading the number.** A proposer screens a
candidate selection in one pass to find every transaction that cannot execute,
then builds a block from what survives. The refusals that pass finds belong to
a block that will never exist. Counting them would make the series a measure of
proposer effort rather than of chain behaviour, and it would do so unevenly:

* **Screening attempts may REPEAT.** The same permanently-invalid transaction
  can be screened by every proposer that selects it, and by the same proposer on
  successive slots until it is evicted from the mempool. One offending
  transaction could therefore contribute many counts while producing no receipt
  at all.
* **Screening attempts do NOT correspond to committed receipts.** A screened-out
  transaction is absent from the block. There is no receipt, no fee, and nothing
  an importing node ever sees. A dashboard mixing the two would show refusals
  with no on-chain trace behind them.
* **The counts are proposer-local.** Screening is proposer policy; an importing
  node does no screening. So the same chain history would produce different
  totals on a validator and on a full node, and comparing two validators'
  counters -- which `wave1-monitor.sh agree` does -- would report disagreement
  that is not disagreement.

So a Wave 1 activation signal read from this counter is a count of refusals that
actually reached the chain. That is the property that makes the cross-validator
comparison meaningful: two validators importing the same blocks see the same
receipts, and therefore the same increments.

Screening has its own reporting: `ProposalScreening` records every offender,
its class, and the bytes charged, and `PoAEngine::proposal_executions` counts
screening passes. Those are the numbers to read when the question is what a
proposer is spending its slot on, and they are separate on purpose.

## 6. Related

* [activation-rollout-evidence.md](activation-rollout-evidence.md) — the
  stage-1 and stage-2 evidence procedures and the abort rule.
* [production-checklist.md](production-checklist.md)
* `docs/lane-a/ACTIVATION-PROPOSAL.json` — the wave membership and the
  prerequisites, with no heights.
* `docs/lane-a/ACTIVATION-DECISION-PACKET.md` §0.8 — the monitoring gap this
  page closes, and the eight instruments it does not.
