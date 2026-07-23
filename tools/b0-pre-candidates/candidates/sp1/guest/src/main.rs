//! Official SP1 6.3.1 guest for the two frozen B0-PRE statements.
//!
//! This is a THIN wrapper: it owns only the SP1 zkVM I/O. All semantics live in
//! the candidate-neutral `b0-pre-guest-core` (the SAME crate the RISC Zero guest
//! calls), so both candidates prove logically identical statement fixtures.
//!
//! Flow:
//!   1. read the guest-input envelope (public statement + private witnesses) as
//!      raw bytes;
//!   2. `b0_pre_guest_core::run` strictly decodes it, authenticates every witness
//!      against the statement, re-executes the frozen integer transformer, and
//!      recomputes every public output — returning the `computation_statement_hash`
//!      journal, or aborting on ANY mismatch (a false/malformed statement yields
//!      no valid proof);
//!   3. commit ONLY that 32-byte journal as the public output. No program id,
//!      verifier key, cycle count, or host-only field is exposed.
//!
//! Building/proving this ELF requires the pinned SP1 6.3.1 guest toolchain in the
//! venue container; it is NOT buildable off-venue (see NOT_YET_REPRODUCED.md and
//! docs/b0-pre/GUEST_SOURCE.md). The guest identity (ELF/vkey) is a venue-built
//! artifact and does not exist yet.
#![no_main]

sp1_zkvm::entrypoint!(main);

pub fn main() {
    // Raw guest-input envelope bytes (paired with the host `stdin.write`).
    let input: Vec<u8> = sp1_zkvm::io::read();
    let journal = b0_pre_guest_core::run(&input)
        .expect("B0-PRE official guest: witness/statement verification failed");
    // The single public output: computation_statement_hash (32 bytes).
    sp1_zkvm::io::commit_slice(&journal);
}
