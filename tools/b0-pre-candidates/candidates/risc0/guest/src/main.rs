//! Official RISC Zero 3.0.5 guest for the two frozen B0-PRE statements.
//!
//! This is a THIN wrapper: it owns only the RISC Zero zkVM I/O. All semantics
//! live in the candidate-neutral `b0-pre-guest-core` (the SAME crate the SP1
//! guest calls), so both candidates prove logically identical statement fixtures.
//!
//! Flow:
//!   1. read the guest-input envelope (public statement + private witnesses) as
//!      raw bytes;
//!   2. `b0_pre_guest_core::run` strictly decodes it, authenticates every witness
//!      against the statement, re-executes the frozen integer transformer, and
//!      recomputes every public output — returning the `computation_statement_hash`
//!      journal, or aborting on ANY mismatch (a false/malformed statement yields
//!      no valid receipt);
//!   3. commit ONLY that 32-byte journal to the receipt journal. No image id,
//!      verifier key, cycle count, or host-only field is exposed.
//!
//! Building/proving this ELF requires the pinned RISC Zero 3.0.5 toolchain in the
//! native x86_64 venue container; it is NOT buildable off-venue (see
//! NOT_YET_REPRODUCED.md and docs/b0-pre/GUEST_SOURCE.md). The guest identity
//! (ELF/image id) is a venue-built artifact and does not exist yet.
#![no_main]

use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

fn main() {
    // Raw guest-input envelope bytes (paired with the host `env.write`).
    let input: Vec<u8> = env::read();
    let journal = b0_pre_guest_core::run(&input)
        .expect("B0-PRE official guest: witness/statement verification failed");
    // The single public output: computation_statement_hash (32 bytes).
    env::commit_slice(&journal);
}
