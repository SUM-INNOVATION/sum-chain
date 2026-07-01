# sumchain-p2p

Peer-to-peer networking for SUM Chain, built on libp2p.

## Purpose

Handles transaction and block gossip, peer discovery, message routing, and
block synchronization between nodes.

## Main modules

- `network` — `NetworkService` with its `NetworkCommand` / `NetworkEvent`
  interface and `RateLimitConfig`.
- `behaviour` — `SumChainBehaviour` (the libp2p network behaviour) and
  `NetworkSecurityConfig`.
- `block_syncer` — `BlockSyncer`, `BlockSyncerConfig`, `SyncStats`.
- `sync` — `SyncRequest` / `SyncResponse` and `MAX_BLOCKS_PER_REQUEST`.
- `peer_manager` — peer tracking and scoring.
- `config` — `NetworkConfig`.
- `node_key` — `load_or_generate_keypair`.
- `topics` — gossipsub topic names (transactions, blocks, BFT messages).

## Public interfaces

- `NetworkService`, `NetworkCommand`, `NetworkEvent`.
- `NetworkConfig`, `SumChainBehaviour`, `NetworkSecurityConfig`.
- `BlockSyncer`, `BlockSyncerConfig`, `SyncRequest`, `SyncResponse`.
- `load_or_generate_keypair`, `topics`.

## Not for

- Consensus / block production — see `sumchain-consensus`.
- Client/RPC access — see `sumchain-rpc`.
