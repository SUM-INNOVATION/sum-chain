//! Gas metering for contract execution.

use crate::{RuntimeError, Result};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Gas unit type
pub type Gas = u64;

/// Gas costs for various operations
#[derive(Debug, Clone)]
pub struct GasCosts {
    // === Base costs ===
    /// Base cost for any contract call
    pub call_base: Gas,
    /// Base cost for contract deployment
    pub deploy_base: Gas,

    // === WASM execution ===
    /// Cost per WASM instruction (approximate)
    pub wasm_instruction: Gas,
    /// Cost for memory allocation (per page = 64KB)
    pub memory_page: Gas,

    // === Storage operations ===
    /// Base cost for storage read
    pub storage_read_base: Gas,
    /// Cost per byte read from storage
    pub storage_read_per_byte: Gas,
    /// Base cost for storage write
    pub storage_write_base: Gas,
    /// Cost per byte written to storage
    pub storage_write_per_byte: Gas,
    /// Cost for storage deletion
    pub storage_delete: Gas,

    // === Cryptographic operations ===
    /// Blake3 hash base cost
    pub blake3_base: Gas,
    /// Blake3 cost per byte
    pub blake3_per_byte: Gas,
    /// Ed25519 signature verification
    pub ed25519_verify: Gas,
    /// secp256k1 signature verification (for bridge)
    pub secp256k1_verify: Gas,

    // === Cross-contract calls ===
    /// Base cost for calling another contract
    pub cross_call_base: Gas,

    // === Events and logs ===
    /// Base cost for emitting an event
    pub event_base: Gas,
    /// Cost per byte in event data
    pub event_per_byte: Gas,
    /// Base cost for log entry
    pub log_base: Gas,
    /// Cost per byte in log data
    pub log_per_byte: Gas,

    // === Value transfer ===
    /// Cost for transferring native currency
    pub transfer: Gas,
}

impl Default for GasCosts {
    fn default() -> Self {
        Self {
            // Base costs
            call_base: 1_000,
            deploy_base: 10_000,

            // WASM execution
            wasm_instruction: 1,
            memory_page: 1_000,

            // Storage (expensive to discourage bloat)
            storage_read_base: 200,
            storage_read_per_byte: 1,
            storage_write_base: 5_000,
            storage_write_per_byte: 50,
            storage_delete: 500,

            // Cryptography
            blake3_base: 100,
            blake3_per_byte: 1,
            ed25519_verify: 2_000,
            secp256k1_verify: 3_000,

            // Cross-contract
            cross_call_base: 5_000,

            // Events and logs
            event_base: 500,
            event_per_byte: 5,
            log_base: 100,
            log_per_byte: 1,

            // Transfer
            transfer: 500,
        }
    }
}

/// Gas meter for tracking gas consumption during execution
#[derive(Debug)]
pub struct GasMeter {
    /// Gas limit for this execution
    limit: Gas,
    /// Gas used so far
    used: Arc<AtomicU64>,
    /// Gas costs configuration
    costs: GasCosts,
}

impl GasMeter {
    /// Create a new gas meter with the given limit
    pub fn new(limit: Gas) -> Self {
        Self {
            limit,
            used: Arc::new(AtomicU64::new(0)),
            costs: GasCosts::default(),
        }
    }

    /// Create a new gas meter with custom costs
    pub fn with_costs(limit: Gas, costs: GasCosts) -> Self {
        Self {
            limit,
            used: Arc::new(AtomicU64::new(0)),
            costs,
        }
    }

    /// Get the gas limit
    pub fn limit(&self) -> Gas {
        self.limit
    }

    /// Get gas used so far
    pub fn used(&self) -> Gas {
        self.used.load(Ordering::SeqCst)
    }

    /// Get remaining gas
    pub fn remaining(&self) -> Gas {
        self.limit.saturating_sub(self.used())
    }

    /// Get gas costs configuration
    pub fn costs(&self) -> &GasCosts {
        &self.costs
    }

    /// Consume gas, returning error if limit exceeded
    pub fn consume(&self, amount: Gas) -> Result<()> {
        let prev = self.used.fetch_add(amount, Ordering::SeqCst);
        let new_used = prev.saturating_add(amount);

        if new_used > self.limit {
            Err(RuntimeError::OutOfGas {
                used: new_used,
                limit: self.limit,
            })
        } else {
            Ok(())
        }
    }

    /// Consume gas for WASM instructions
    pub fn consume_wasm(&self, instruction_count: u64) -> Result<()> {
        self.consume(instruction_count.saturating_mul(self.costs.wasm_instruction))
    }

    /// Consume gas for storage read
    pub fn consume_storage_read(&self, bytes: usize) -> Result<()> {
        let cost = self.costs.storage_read_base
            + (bytes as Gas).saturating_mul(self.costs.storage_read_per_byte);
        self.consume(cost)
    }

    /// Consume gas for storage write
    pub fn consume_storage_write(&self, bytes: usize) -> Result<()> {
        let cost = self.costs.storage_write_base
            + (bytes as Gas).saturating_mul(self.costs.storage_write_per_byte);
        self.consume(cost)
    }

    /// Consume gas for storage delete
    pub fn consume_storage_delete(&self) -> Result<()> {
        self.consume(self.costs.storage_delete)
    }

    /// Consume gas for Blake3 hashing
    pub fn consume_blake3(&self, bytes: usize) -> Result<()> {
        let cost = self.costs.blake3_base
            + (bytes as Gas).saturating_mul(self.costs.blake3_per_byte);
        self.consume(cost)
    }

    /// Consume gas for Ed25519 verification
    pub fn consume_ed25519_verify(&self) -> Result<()> {
        self.consume(self.costs.ed25519_verify)
    }

    /// Consume gas for secp256k1 verification
    pub fn consume_secp256k1_verify(&self) -> Result<()> {
        self.consume(self.costs.secp256k1_verify)
    }

    /// Consume gas for cross-contract call
    pub fn consume_cross_call(&self) -> Result<()> {
        self.consume(self.costs.cross_call_base)
    }

    /// Consume gas for event emission
    pub fn consume_event(&self, data_bytes: usize) -> Result<()> {
        let cost = self.costs.event_base
            + (data_bytes as Gas).saturating_mul(self.costs.event_per_byte);
        self.consume(cost)
    }

    /// Consume gas for log entry
    pub fn consume_log(&self, data_bytes: usize) -> Result<()> {
        let cost = self.costs.log_base
            + (data_bytes as Gas).saturating_mul(self.costs.log_per_byte);
        self.consume(cost)
    }

    /// Consume gas for value transfer
    pub fn consume_transfer(&self) -> Result<()> {
        self.consume(self.costs.transfer)
    }

    /// Consume gas for memory allocation
    pub fn consume_memory(&self, pages: u32) -> Result<()> {
        self.consume((pages as Gas).saturating_mul(self.costs.memory_page))
    }

    /// Get a clone of the used counter (for sharing with WASM)
    pub fn used_counter(&self) -> Arc<AtomicU64> {
        self.used.clone()
    }

    /// Create a sub-meter with a portion of remaining gas
    pub fn sub_meter(&self, gas_for_call: Gas) -> Result<GasMeter> {
        let remaining = self.remaining();
        if gas_for_call > remaining {
            return Err(RuntimeError::OutOfGas {
                used: self.used(),
                limit: self.limit,
            });
        }

        // Reserve gas for the sub-call
        self.consume(gas_for_call)?;

        Ok(GasMeter {
            limit: gas_for_call,
            used: Arc::new(AtomicU64::new(0)),
            costs: self.costs.clone(),
        })
    }

    /// Refund unused gas from a sub-meter
    pub fn refund(&self, sub_meter: &GasMeter) {
        let unused = sub_meter.remaining();
        // Subtract from used (atomic)
        self.used.fetch_sub(unused, Ordering::SeqCst);
    }
}

impl Clone for GasMeter {
    fn clone(&self) -> Self {
        Self {
            limit: self.limit,
            used: Arc::new(AtomicU64::new(self.used())),
            costs: self.costs.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gas_consumption() {
        let meter = GasMeter::new(1000);

        assert!(meter.consume(500).is_ok());
        assert_eq!(meter.used(), 500);
        assert_eq!(meter.remaining(), 500);

        assert!(meter.consume(500).is_ok());
        assert_eq!(meter.used(), 1000);
        assert_eq!(meter.remaining(), 0);

        // Should fail - out of gas
        assert!(meter.consume(1).is_err());
    }

    #[test]
    fn test_sub_meter() {
        let meter = GasMeter::new(1000);

        let sub = meter.sub_meter(500).unwrap();
        assert_eq!(sub.limit(), 500);
        assert_eq!(sub.used(), 0);
        assert_eq!(meter.used(), 500); // Reserved

        sub.consume(200).unwrap();
        assert_eq!(sub.remaining(), 300);

        meter.refund(&sub);
        assert_eq!(meter.used(), 200); // Only consumed gas charged
    }
}
