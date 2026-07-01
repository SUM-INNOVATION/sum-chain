# sumchain-consensus

Consensus engines for SUM Chain: Proof of Authority (production) behind a common
engine trait.

## Purpose

Handles block proposal, fork choice, and finality. Proof of Authority (PoA) is
the production consensus — round-robin proposer selection with depth-based
finality. A Tendermint-style BFT engine is present as an experimental/roadmap
alternative behind the same trait.

## Main modules

- `poa` — `PoAEngine`, the production PoA consensus (round-robin proposer,
  longest-chain fork choice, depth-based finality).
- `engine` — the `ConsensusEngine` trait and `ConsensusEvent`, the shared
  interface implementations expose.
- `bft` — `BftEngine`, an experimental Tendermint-style engine on the roadmap;
  PoA is the engine used in production.

## Public interfaces

- `PoAEngine` — production consensus engine.
- `ConsensusEngine`, `ConsensusEvent` — the engine trait and event type.
- `BftEngine` — experimental BFT engine.

## Not for

- Transaction execution — see `sumchain-state`.
- Networking / block gossip — see `sumchain-p2p`.
