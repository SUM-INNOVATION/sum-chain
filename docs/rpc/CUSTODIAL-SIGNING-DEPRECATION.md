# Custodial signing methods: off by default, deprecated

Six RPC methods take the caller's raw private key and sign the transaction on
the server:

| Family | Methods |
|---|---|
| DocClass (SRC-81X) | `docclass_registerAcademicIssuer`, `docclass_issueAcademicCredential`, `docclass_revokeAcademicCredential` |
| Employment (SRC-88X) | `employment_registerIssuer`, `employment_createCredential`, `employment_revokeCredential` |

A server should never receive a private key: anything that can read the
request (the node, a proxy in front of it, a log, a crash dump) can read the
key, and a key that has been sent once cannot be made private again. These
methods are therefore **off by default** and deprecated.

| | DocClass | Employment |
|---|---|---|
| Custodial methods | Off by default; opt in with `unsafe_custodial_docclass_methods` | Off by default; opt in with `unsafe_custodial_employment_methods` |
| Client-side replacement | **Exists** (#333): `docclass_buildTransaction` and `sumchain docclass` | **Exists** (not yet in a release): `employment_buildTransaction` and `sumchain employment` |

## What changes

- **Off by default.** A node serves neither family unless its operator opts in.
  Off, each method answers with JSON-RPC error **`-32005`** and fixed text,
  before it uses the key or any other field of the request. Nothing is queued
  or broadcast. The text never repeats anything from the request.
- **Per family.** The two families are enabled separately.
- **On, with warnings.** An enabled node logs a deprecation warning at startup
  and on every call. The warning names the method only, never the request.
- **Safer handling while they remain.** The key in a request is held redacted
  (`Debug` prints `<redacted>`) and zeroized when dropped. A malformed key is
  refused with one fixed message that repeats no character and no position.
  This covers the node's own copies only; the transport's request buffers are
  outside it.
- **Unchanged:** the request and response JSON, the transactions an enabled
  node builds, and every other RPC method. No consensus or execution change.
- **Archived documentation.** Archived guides that showed requests carrying a
  private key now say not to send one and point to client-side signing. The
  RPC hostname they used, which the project no longer uses, is replaced by
  `https://rpc.sumchain.io`.

## What this does not do

Turning these methods off and removing the old instructions does **not**
revoke or protect any key that was already sent to a server or published.
Copies in logs, proxies, backups and repository history remain. Treat such a
key as exposed: its owner must replace it. Documentation cleanup is not key
revocation.

It also cannot stop a client from transmitting a key: the request still
reaches the node and anything in front of it, which only refuse to use the
key. Nothing changes on a running network until its nodes run a release
containing this change with the defaults left off.

## For clients

### DocClass: use the client-side path

Build the transaction without a key, sign it on the client, submit the signed
bytes:

1. `docclass_buildTransaction` takes the sender's **address** and the
   operation's public fields and returns the unsigned transaction and its
   signing hash.
2. `sumchain docclass <command>` does the whole flow locally: it builds the
   transaction, checks it against the node's builder, signs it with a local key
   file and submits it with `send_raw_transaction`. `--dry-run` shows what
   would be sent without signing.

See [`docs/subprotocols/DOCCLASS-CLIENT-SIGNING.md`](../subprotocols/DOCCLASS-CLIENT-SIGNING.md).

| Custodial method | Client-side replacement |
|---|---|
| `docclass_registerAcademicIssuer` | `register_academic_issuer` op / `sumchain docclass register-issuer` |
| `docclass_issueAcademicCredential` | `issue_academic_credential` op / `sumchain docclass issue` |
| `docclass_revokeAcademicCredential` | `revoke_credential` op / `sumchain docclass revoke` |

On the same chain state the replacement has the same on-chain effect (tested
in `crates/rpc/tests/custodial_client_equivalence.rs`). Two visible
differences: the issuer key id a registration records (`primary` rather than
`primary-key`), and credential ids, which the replacement derives with the
chain's `generate_credential_id`. The chain accepts both; each path reports the
id it used.

The replacement also covers operations the custodial methods never offered:
suspend, reactivate, supersede, update issuer, rotate issuer key and
deactivate issuer.

### Employment: use the client-side path

The same flow as DocClass:

1. `employment_buildTransaction` takes the sender's **address** and the
   operation's public fields and returns the unsigned transaction and its
   signing hash.
2. `sumchain employment <command>` builds the transaction, checks it against
   the node's builder, signs it with a local key file and submits it with
   `send_raw_transaction`. `--dry-run` shows what would be sent without
   signing.

See [`docs/subprotocols/EMPLOYMENT-CLIENT-SIGNING.md`](../subprotocols/EMPLOYMENT-CLIENT-SIGNING.md).

| Custodial method | Client-side replacement |
|---|---|
| `employment_registerIssuer` | `register_issuer` op / `sumchain employment register-issuer` |
| `employment_createCredential` | `create_employment` op / `sumchain employment create` |
| `employment_revokeCredential` | `revoke_employment` op / `sumchain employment revoke` |

On the same chain state the replacement has the same on-chain effect (tested
in `crates/rpc/tests/custodial_employment_client_equivalence.rs`). Given the
same fields, a registration or credential creation is byte-identical to the
custodial method's transaction. A revocation carries only the two fields the
chain reads; the custodial method also appended a time and the reason text,
which the chain ignores. The client hashes the reason into the revocation
reference and never sends it.

Until a node runs a release containing the employment builder, an operator who
must keep serving existing employment clients can re-enable that family alone
(below).

## For node operators

```toml
[rpc]
# Both default to false.
unsafe_custodial_docclass_methods = false
unsafe_custodial_employment_methods = false
```

or, overriding the config file:

```sh
sumchain run ... --rpc-unsafe-custodial-docclass-methods true
sumchain run ... --rpc-unsafe-custodial-employment-methods true
```

Enable a family only to keep serving known existing clients while they
migrate, and only on a node whose RPC is not reachable by untrusted parties.
Re-enabling does not make sending a key safe; it only keeps old clients
working.

## Timeline

| Step | When |
|---|---|
| Off by default; opt-in flags; warnings | This release |
| Employment client-side builder | Implemented; release `<to be set>` |
| Removal of the six methods | `<to be set>` (not before the employment builder ships) |
