# sumc-sdk-macros

Procedural macros for the SUM Chain smart-contract SDK.

## Purpose

Provides the attribute macros that mark contract structs and methods so
`sumc-sdk` can generate the contract entry points.

## Main modules

A single procedural-macro crate exposing attribute macros:

- `#[contract]` — marks a struct as a contract.
- `#[init]` — marks the constructor method.
- `#[call]` — marks a public method that modifies state.
- `#[view]` — marks a public method that only reads state.
- `#[payable]` — marks a method that may receive value.

## Public interfaces

The attribute macros `contract`, `init`, `call`, `view`, and `payable`. These
are normally used through `sumc-sdk` rather than imported directly.

## Not for

- Contract authoring APIs — those (prelude, env, storage, types) live in
  `sumc-sdk`.
- Runtime execution — see `sumc-runtime`.
