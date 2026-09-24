# downgrade-probe

Reproduces what the deployed 0.2.0-era node does when it opens a data directory
this release has opened. `rocksdb` is pinned to 0.22.0 in `Cargo.lock`, the
version every 0.2.0-era lockfile uses, so run it with `--locked`.

    cd tools/lane-b/downgrade-probe
    cargo run --locked --release --bin cfprobe2 -- <empty-scratch-dir>

`cfprobe2` writes 2000 rows into `blocks`, `state`, `meta` and
`application_journal` through this tree's storage crate, then plays the 0.2.0
open path with raw RocksDB calls: open with the 187 families 0.2.0 knows
(everything except `application_journal`), treat the "Invalid argument" as
corruption, run `DB::repair` with no family descriptors, reopen. Observed:

    OLD-SET OPEN ERROR: Invalid argument: Column families not opened: application_journal
    repair: CFs before=189 after=1
    rows in blocks / state / meta after repair: 0 / 0 / 0

It simulates the OLD binary on purpose, so the result does not depend on the
fix in this branch -- this is the reason Stage 1's only safe rollback is a
volume snapshot taken before the new binary first opens the volume
(docs/operations/production-checklist.md, item 5).

`main.rs` is the data-free version (open error and classification only).
`genhash` rebuilds genesis block 0 from a genesis file, which is how the root
`genesis.json` was matched to the live chain's block 0.
