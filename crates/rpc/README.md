# sumchain-rpc

JSON-RPC server for SUM Chain — query chain state and submit transactions.

## Purpose

Exposes the node's read/write surface over JSON-RPC (HTTP), plus auth, rate
limiting, health, and metrics endpoints.

## Main modules

- `api` — the `#[rpc]` trait defining every JSON-RPC method (the API contract).
- `server` — `RpcServer`, the handler implementation backed by chain stores.
- `types` — request/response DTOs returned over the wire.
- `auth`, `rate_limit`, `health`, `metrics` — operational middleware/endpoints.

## Public interfaces

- `RpcServer` (+ `RpcTimeoutConfig`, provider traits) — construct and run the server.
- `RpcError` — error type surfaced to callers.
- `RpcAuthConfig` / `ApiKeyValidator`, `RateLimitConfig`, `HealthServer`, `Metrics`.

The method list and supported public surface are documented in
[`docs/rpc/api-reference.md`](../../docs/rpc/api-reference.md); token-family
usage examples are in [`docs/tokens.md`](../../docs/tokens.md).

## Not for

- Client use — consume the API via `sumc-sdk` or `sdk/typescript`, not this crate.
- Chain logic — execution/consensus live in `sumchain-state` / `sumchain-consensus`.
