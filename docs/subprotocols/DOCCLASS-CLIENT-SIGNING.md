# DocClass client-side signing

Academic issuers and their credentials can be managed without sending a private
key to any server. The transaction is built and signed on the client; the node
only sees the signed transaction.

Two pieces do this:

- **`docclass_buildTransaction`**, a no-key RPC builder. It takes the sender's
  address and the operation's public fields and returns an unsigned
  `TransactionV2` and its signing hash. It never signs, submits or executes
  anything. See the builder table in [`docs/rpc/api-reference.md`](../rpc/api-reference.md).
- **`sumchain docclass`**, a command group in the `sumchain` binary, modelled on
  `sumchain transfer`.

Both use one construction (`sumchain_primitives::docclass_build`), so for the
same explicit inputs they produce the same bytes.

## What a command does

1. Reads the chain id and the sender's nonce from `--rpc` (and, for an issue
   that omits them, the sender's registered name and jurisdiction).
2. Builds the transaction locally, every field explicit.
3. Asks the node's `docclass_buildTransaction` for the same transaction and
   **refuses to sign** if the node's bytes or signing hash differ. Use
   `--no-builder-check` only against a node that has no builder.
4. With `--dry-run`, prints the summary and the signing hash and stops. Nothing
   is signed or sent, and `--from <address>` can stand in for `--key`.
5. Otherwise signs the locally built transaction with `--key` and submits it
   with `send_raw_transaction`.

The key file is the same JSON array of 32 bytes `sumchain transfer` reads. It is
held in memory that is zeroed after use, and an unreadable or malformed file
produces one fixed message that repeats nothing from the file.

## Commands

Options common to every command: `--key <file>`, `--from <address>` (dry run
only), `--rpc <url>` (default `http://localhost:8545`), `--fee <base units>`,
`--dry-run`, `--no-builder-check`.

| Command | Operation |
|---|---|
| `register-issuer --name … --jurisdiction XX --subcodes 810,811,812 [--stake N]` | Register the sender as an educational issuer; records the sender's own public key |
| `issue --holder <address> --subcode 811 --subject-commitment … --schema-hash … --content-commitment … --title … --credential-type … --issue-date … [--attribute name=value]…` | Issue an academic credential; prints its id |
| `revoke --credential-id … [--reason N]` | Revoke a credential the sender issued |
| `suspend --credential-id … [--reason N]` / `reactivate --credential-id …` | Suspend or reactivate one |
| `supersede --old-credential-id … --new-credential-id …` | Supersede one with a newer credential |
| `rotate-issuer-key --new-key-id … --new-public-key … --old-key-id …` | Add a new issuer key and retire the old one |
| `update-issuer --record <file.json>` | Replace the sender's issuer record with a complete record (the `update_issuer.issuer` request shape) |
| `deactivate-issuer [--issuer <address>]` | Deactivate the sender, or, signed by the chain's DocClass admin, another issuer |

Values shown as `…` are hex (32 bytes) for commitments, hashes and ids, and
plain text otherwise. Times are milliseconds and default to now.

## Example (synthetic)

```sh
# Check what would be sent, without a key:
sumchain docclass --from <issuer-address> --dry-run \
  revoke --credential-id <credential-id-hex> --reason 1

# Sign locally and submit:
sumchain docclass --key ./issuer-key.json \
  revoke --credential-id <credential-id-hex> --reason 1
```

The chain decides whether an operation is authorized. The builder and the
commands check only that the request is well formed: a two-letter jurisdiction,
academic subcodes, a public key that belongs to the sender, an issuer record
for the sender's own address.
