//! Frozen scalars, dimensions, official bounds, and decoder maxima (plan §2/§8/§20).

// Fixed scalars (a byte carrying any other value is rejected on decode).
pub const SCHEMA_VERSION: u16 = 1;
pub const ALGORITHM_VERSION: u16 = 1;
pub const SOFTMAX_VARIANT_ID: u16 = 1;
pub const TOKEN_INPUT_SCHEME_ID: u16 = 1;
pub const FIXED_POINT_VERSION: u16 = 1;
pub const FIXED_POINT_SCALE_LOG2: u8 = 8;
pub const WORKLOAD_ARCH_ID: u32 = 0x5230_0001;
pub const WEIGHT_SCHEDULE_VERSION: u32 = 0;
pub const OUTPUT_MANIFEST_SCHEMA_VERSION: u16 = 1;

// Frozen model dimensions.
pub const D_MODEL: u32 = 8;
pub const N_HEADS: u32 = 2;
pub const HEAD_DIM: u16 = 4;
pub const FFN_DIM: u16 = 16;
pub const VOCAB_SIZE: u32 = 16;
pub const MAX_SEQ: u32 = 8;

// Frozen official statement bounds (§20); official statements require equality.
pub const MAX_D_MODEL: u32 = 8;
pub const MAX_SEQ_LEN: u32 = 8;
pub const MAX_OUTPUT_TOKENS: u32 = 8;
pub const MAX_MANIFEST_SLOTS: u32 = 3;
pub const MAX_STATE_BYTES: u64 = 2761;
pub const MAX_CYCLES: u64 = 0;

// Controlled chain-verification reference envelope (§23): the verification run is
// pinned to exactly this configured cpuset and memory limit for the B0
// candidate comparison. This is NOT a validator hardware minimum -- validators
// need no minimum CPU or RAM to participate, and detected host hardware is not
// gated. Qualification is performance-based (worst-arch verify p99 / per-block
// budget) under this envelope; a machine that cannot keep pace has an
// operational-liveness condition, not a consensus/proof-system disqualification.
pub const VALIDATOR_VERIFY_REFERENCE_CORES: u32 = 2;
pub const VALIDATOR_VERIFY_REFERENCE_RAM_BYTES: u64 = 4 << 30;
pub const VALIDATOR_AGGREGATE_VERIFY_BUDGET_NS_PER_BLOCK: u64 = 300_000_000; // 300 ms/block

// Recommended default local resource-budget an OmniNode operator may configure
// per device. Not consensus, proof validity, candidate selection, or hardware
// eligibility.
pub const LOCAL_RESOURCE_BUDGET_DEFAULT_PERCENT: u32 = 35;

// General decoder maxima (§8) — larger than the official bounds; schema-valid
// but B0-selection-ineligible statements may use up to these.
pub const OUTPUT_MANIFEST_MAX_SLOTS: u32 = 256;
pub const INPUT_MANIFEST_MAX_SLOTS: u32 = 8;

// Frozen R0 evidence completeness, per candidate (§13/§23). Measurement grid is
// 2 official statements × 2 architectures × 10 measured proofs.
pub const OFFICIAL_ITERATIONS_PER_CELL: u32 = 10;
pub const OFFICIAL_MEASURED_PROOFS: u32 = 40; // 2 × 2 × 10
pub const OFFICIAL_VERIFY_TIMING_SAMPLES: u32 = 4000; // 40 × 100
pub const OFFICIAL_PROVE_TIME_SAMPLES: u32 = 40;
pub const OFFICIAL_PROOF_BYTES_SAMPLES: u32 = 40;
pub const OFFICIAL_SETUP_SAMPLES: u32 = 40; // one host_setup_ns per initialized verify batch
pub const OFFICIAL_PROVING_RUN_RSS: u32 = 40;
pub const OFFICIAL_VERIFY_BATCH_RSS: u32 = 40;
pub const OFFICIAL_PROVENANCE_SNAPSHOTS: u32 = 4; // {x86,arm} × {proving,verification}
