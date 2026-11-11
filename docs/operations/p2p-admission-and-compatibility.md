# P2P admission and peer compatibility — operator notes

Two behaviour changes in this release are visible from outside the node and are
not visible from its logs alone. Both are accepted; neither is a defect
awaiting work. This page is the operator-facing statement of what changed, what
the numbers are, and what to watch.

> **Status:** current for this release.
> **Scope:** `crates/p2p` only — peer admission and the two-phase protocol
> compatibility policy. Nothing here is consensus.

---

## 1. The inbound peer limit now BINDS

### What changed

`PeerManager::can_accept_inbound` used to have no caller anywhere. The
connection limits it consults — and the `max_inbound` in `NetworkConfig` —
described a policy that nothing in the swarm loop applied; the only refusal
that actually fired was a separate, narrower ban check written beside it.

`SwarmEvent::ConnectionEstablished` in `NetworkService::run`
(`crates/p2p/src/network.rs`) now calls the predicate, for the inbound half of
every connection, **before** the peer is registered and before `PeerConnected`
is announced. The refusal closes the connection rather than merely skipping
registration.

### The operational correction this produces

**A node holding 50 inbound peers now refuses the 51st. It previously accepted
it.** That is the whole of the change an operator will observe, and it is
accepted as an operational correction: the limit was always the stated policy,
it simply was not enforced.

Expect, on a node that was previously running with more than 50 inbound peers:

* the inbound peer count to settle at the limit rather than drifting above it;
* refused peers to see the connection closed immediately after it is
  established, not a dial-time rejection;
* no change at all on a node that never reached the limit — which is every node
  of a small devnet.

An OUTBOUND connection is never refused on a capacity limit. It is one this
node dialled, so refusing it on an inbound or per-IP limit would be refusing
this node's own decision after the fact. Only the peer-facing half — ban and
reputation floor, `PeerManager::peer_is_admissible` — applies to the outbound
side.

### The numbers, and how to change them

| limit | default | what it bounds |
|---|---|---|
| `max_inbound` | **50** | inbound connections |
| `max_outbound` | **50** | outbound connections |
| `max_total` | **100** | both directions together |
| `max_per_ip` | 3 | connections from one remote IP — **inert, see below** |

Defaults are `ConnectionLimits::default()` in
`crates/p2p/src/peer_manager.rs`. They are overridable through
`NetworkConfig` (`crates/p2p/src/config.rs`): `NetworkService::new` derives
`max_inbound` and `max_outbound` from it and sets
`max_total = max_inbound + max_outbound`, which is how the default 100 arises.

**Read this before trying to change them on a release node.** The `sumchain`
binary constructs its `NetworkConfig` with `..Default::default()` for the two
connection-limit fields (`crates/node/src/main.rs`), so the shipped node runs
50 / 50 / 100 and nothing in `config.toml` moves those numbers. In particular:

* `[network] max_peers` in `config.toml` (`crates/node/src/config.rs`) is
  parsed into `NetworkSettings::max_peers` and **read by nothing**. It does not
  set the inbound limit, the outbound limit, or the total. Setting it to 500
  changes no behaviour whatsoever.
* Raising the limits today means changing the values a binary is built with, or
  changing `main.rs` to thread the setting through. It is not a configuration
  change, and an operator who believes it is will be surprised at 50 inbound
  peers rather than at whatever they wrote down.

### `max_per_ip` is deliberately INERT

`max_per_ip` defaults to 3, and **it never fires.** The call site in
`SwarmEvent::ConnectionEstablished` passes `remote_ip: None`, so the per-IP
clause in `can_accept_inbound` is skipped for every connection on a release
node.

This is deliberate and is stated rather than fixed. Every node of a loopback
devnet shares `127.0.0.1`: threading the remote address through would make each
node start refusing its fourth peer the moment the value became live, which is
a devnet that silently stops forming a full mesh. Making it live is a separate
decision about what the default should be, not part of giving the predicate a
caller.

Two consequences an operator should hold:

* **Do not rely on `max_per_ip` for any abuse protection.** It bounds nothing
  today. A single remote host may open as many inbound connections as the
  global `max_inbound` allows.
* If it is ever made live, `3` is almost certainly the wrong value for a
  loopback or single-host deployment, and the change must come with a default
  that is not 3.

### Where this is pinned

* `crates/p2p/src/peer_manager.rs` — `can_accept_inbound`, and the
  `ConnectionLimits` defaults.
* `crates/p2p/src/network.rs` — the `ConnectionEstablished` arm that calls it.
* `crates/p2p/tests/protocol_enforcement.rs` —
  `the_disconnect_command_reaches_the_swarm_and_the_admission_gate_precedes_registration`
  holds the gate ahead of registration and ahead of the `PeerConnected`
  announcement, which no out-of-process test can observe.
* `crates/p2p/src/peer_manager.rs::tests::test_connection_limits` — the limit
  arithmetic itself.

---

## 2. Peer-compatibility state resets on restart — accepted below the enforcement height, fail-closed above it

### What the registry is

`PeerCompatRegistry` (`crates/p2p/src/peer_compat.rs`) records what each peer
has PROVEN about the rules it enforces, from the `GetProtocolId` handshake:

| the peer | state |
|---|---|
| declares our protocol digest | `Verified` |
| declares a different digest | `Incompatible` (permanent, within one process) |
| declares nothing | `Undeclared` |

The policy has a boundary — the chain height in
`ChainParams::peer_protocol_declaration_required_from_height`. Below it (or
with the field unset, which is what every genesis distributed before the field
existed resolves to) an `Undeclared` peer participates. At or above it, an
`Undeclared` peer is refused.

### The accepted property

**The registry is held in memory and nothing persists it. A restart forgets
every declaration.** The two sides of the boundary fail in opposite directions:

* **Below the enforcement height — ACCEPTED.** A restart re-admits a peer this
  node had marked `Incompatible`. Pre-enforcement compatibility state may reset
  on restart. This is a decided property of the release, **not an outstanding
  residual**, and it is not tracked as pending work. The cost is bounded by
  what phase one already means: below the height every node executes the same
  rules, so the re-admitted peer's blocks are blocks this node would have
  produced itself — the same admission phase one already makes for every silent
  peer.
* **At or above the enforcement height — fail-closed, and not negotiable.** A
  restart re-refuses a peer it had VERIFIED, until that peer answers
  `GetProtocolId` again. A verified peer is temporarily treated as undeclared,
  which is a refusal, which is the safe direction. Post-enforcement behaviour
  must remain fail-closed.

The ban in `PeerManager` is forgotten across a restart too, and for the same
reason: it is in memory.

### What an operator should expect

* Restarting a node **below** the enforcement height may briefly reconnect it
  to a peer it had refused. Nothing needs to be done about this.
* Restarting a node **at or above** the enforcement height means a short window
  in which peers it had already verified cannot supply blocks, until each
  re-answers the handshake. Sync resumes on its own; a node that appears
  peer-starved for a few seconds after a restart in phase two is this, and not
  a configuration fault.
* A peer that re-declares a MISMATCH after the restart is refused again
  immediately, in both phases.

### Where this is pinned

`crates/p2p/tests/protocol_enforcement.rs::a_restart_forgets_declarations_and_the_window_fails_closed_above_the_height`
asserts both halves in one test: that a fresh registry forgets both the
verification and the refusal; that at `ENFORCE_FROM`, `ENFORCE_FROM + 1` and
`u64::MAX` a re-forgotten peer is refused until it declares again; and that
below the height the forgotten refusal does re-admit, which is the accepted
half stated as an assertion rather than left to be rediscovered.

If a future change persists the declarations, seeds the registry, or widens the
below-the-height admission, the above-the-height assertions in that test must
keep refusing an undeclared peer. The accepted reset buys nothing above the
height and must not be allowed to leak there.

---

## Related

* [production-checklist.md](production-checklist.md) — the rest of the
  operational surface.
* [validator-memory-floor.md](validator-memory-floor.md) — the 4 GiB supported
  validator memory floor for this release.
