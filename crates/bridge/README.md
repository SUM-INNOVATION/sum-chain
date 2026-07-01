# sumchain-bridge

Cross-chain bridge between Ethereum and SUM Chain.

## Purpose

Implements the SUM Chain side of an asset bridge: watching Ethereum for locked
assets, relaying validator-attested events, and tracking wrapped-token mappings
so ETH/ERC-20/ERC-721 assets can be represented on SUM Chain.

## Main modules

- `relayer` — `BridgeRelayer`, drives deposit/withdrawal relaying.
- `ethereum` — `EthereumClient` and `EthereumWatcher` for the Ethereum side.
- `wrapped_tokens` — `WrappedTokenRegistry`, the wrapped-asset mapping.
- `config` — `BridgeConfig`.
- `types` — shared bridge types.
- `error` — `BridgeError` and `Result`.

## Public interfaces

- `BridgeRelayer`.
- `EthereumClient`, `EthereumWatcher`.
- `WrappedTokenRegistry`.
- `BridgeConfig`, `BridgeError`.

## Not for

- On-chain token/NFT standards — see `sumchain-token` (SRC-20) and
  `sumchain-nft` (SUM-721).
- Consensus / validator attestation internals — see `sumchain-consensus`.
