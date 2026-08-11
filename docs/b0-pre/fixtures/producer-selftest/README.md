# Producer self-test vector (TEST-ONLY)

`producer-dry-run-testonly.bin` is the output of
`measure-produce --dry-run` — the B0-FINAL measurement PRODUCER run over
DETERMINISTIC synthetic raw facts (domain `b0-final-dry-run/v1`), NOT genuine
proofs. It exercises the full production assembly path off-venue and is verified
byte-for-byte by both the reference (`b0-pre-validator`) and the dependency-free
independent verifier crate.

It is **TEST-ONLY** and must never be confused with real measurement evidence:
the SP1 bundle qualifies and the RISC0 x86-only bundle is mechanically disqualified
(`MeasuredProofGrid`), but the underlying proofs are synthetic. Real evidence is
produced only by the venue shell runner over genuine proofs.

`.blake3` is the content address (`= package_id`).
