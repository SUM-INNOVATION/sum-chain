# Employment client-side signing

Employment (SRC-88X) issuers can register and manage employment credentials
without sending a private key to any server. The transaction is built and
signed on the client; the node only sees the signed transaction.

It replaces the deprecated custodial methods (`employment_registerIssuer`,
`employment_createCredential`, `employment_revokeCredential`), which are off by
default; see
[`docs/rpc/CUSTODIAL-SIGNING-DEPRECATION.md`](../rpc/CUSTODIAL-SIGNING-DEPRECATION.md).
It follows the same pattern as
[DocClass client-side signing](DOCCLASS-CLIENT-SIGNING.md).

Two pieces do this:

- **`employment_buildTransaction`**, a no-key RPC builder. It takes the
  sender's address and the operation's public fields and returns an unsigned
  `TransactionV2` and its signing hash. It never signs, submits or executes
  anything. See the builder table in [`docs/rpc/api-reference.md`](../rpc/api-reference.md).
- **`sumchain employment`**, a command group in the `sumchain` binary, modelled
  on `sumchain transfer` and `sumchain docclass`.

Both use one construction (`sumchain_primitives::employment_build`), so for the
same explicit inputs they produce the same bytes.

## What a command does

1. Reads the chain id and the sender's nonce from `--rpc`. When the command
   omits them, it also reads the latest block height (registration), the
   sender's registered display name and issuer class (create), or the
   credential's employee (revoke).
2. Builds the transaction locally, every field explicit.
3. Asks the node's `employment_buildTransaction` for the same transaction and
   **refuses to sign** if the node's bytes or signing hash differ. Use
   `--no-builder-check` only against a node that has no builder.
4. With `--dry-run`, prints the summary and the signing hash and stops. Nothing
   is signed or sent, and `--from <address>` can stand in for `--key`.
5. Otherwise signs the locally built transaction with `--key` and submits it
   with `send_raw_transaction`.

The key file is the same JSON array of 32 bytes `sumchain transfer` and
`sumchain docclass` read, handled the same way: held in memory that is zeroed
after use, and an unreadable or malformed file produces one fixed message that
repeats nothing from the file.

## Commands

Options common to every command: `--key <file>`, `--from <address>` (dry run
only), `--rpc <url>` (default `http://localhost:8545`), `--fee <base units>`
(default 1000000, the custodial methods' fee), `--dry-run`,
`--no-builder-check`.

| Command | Operation |
|---|---|
| `register-issuer --class Employer --display-name … --issuer-commitment … --jurisdiction US --policy-id … [--registered-at-height N] [--registered-at MS]` | Register the sender as an employment issuer |
| `create --employee <address> --employee-ref … --employer-ref … --tenure-commitment … [--role-commitment …] --employment-type FullTime --policy-id … [--valid-from MS] [--expiry MS] [--issuer-name …] [--issuer-class …] [--created-at MS]` | Create an employment credential; prints its employment id |
| `revoke --employment-id … [--employee <address>] [--revocation-ref … \| --reason …] [--revoked-at MS]` | Revoke a credential the sender issued |

Values shown as `…` are hex (32 bytes) for commitments, references and ids, and
plain text otherwise. Times are milliseconds and default to now.

- **Issuer classes:** `GovernmentLabor`, `PayrollProcessor`,
  `RegulatedHrPlatform`, `Peo`, `Employer`, `HrPlatform`, `StaffingAgency`,
  `GigPlatform`.
- **Employment types:** `FullTime`, `PartTime`, `Contract`, `Temporary`,
  `Internship`, `Freelance`, `Gig`.

## Revocation references

A revocation records a 32-byte reference on the credential. Pass one with
`--revocation-ref`, or let the command derive it the way the custodial method
did: BLAKE3 over the employment id, the time (milliseconds, little-endian) and,
if given, `--reason`. The reason text is hashed on the client and is **not**
sent to the node or put in the transaction. The custodial method appended the
time and reason to its transaction after the two fields the chain reads; the
client-side transaction carries only those two fields, with the same on-chain
effect.

## Compatibility with the custodial methods

On the same chain state the replacement has the same on-chain effect (tested in
`crates/rpc/tests/custodial_employment_client_equivalence.rs`):

- **Register and create:** given the same fields, including the times and
  height the server used to choose, the unsigned transaction is byte-identical,
  and so is the employment id.
- **Revoke:** with the same reference, the stored credential is identical; the
  transaction differs only by the trailing time and reason the custodial method
  appended and the chain ignores.

The custodial methods never offered the other Employment operations (issuer
status changes, credential updates, income attestations, proofs), and neither
does this replacement.

## Example (synthetic)

```sh
# Check what would be sent, without a key:
sumchain employment --from <issuer-address> --dry-run \
  revoke --employment-id <employment-id-hex> --reason "contract ended"

# Sign locally and submit:
sumchain employment --key ./issuer-key.json \
  revoke --employment-id <employment-id-hex> --reason "contract ended"
```

The chain decides whether an operation is authorized. The builder and the
commands check only that the request is well formed: known issuer classes and
employment types, 32-byte hex values, a non-empty display name and
jurisdiction, and a credential that always names the sender as its issuer.
