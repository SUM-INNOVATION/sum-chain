//! Memory management for WASM contracts.

use crate::{Result, RuntimeError, MAX_MEMORY_PAGES};

/// Memory allocator helper for WASM linear memory
pub struct MemoryManager {
    /// Current number of pages
    pages: u32,
    /// Maximum pages allowed
    max_pages: u32,
}

impl MemoryManager {
    /// Create a new memory manager
    pub fn new(initial_pages: u32) -> Self {
        Self {
            pages: initial_pages,
            max_pages: MAX_MEMORY_PAGES,
        }
    }

    /// Get current memory size in pages
    pub fn pages(&self) -> u32 {
        self.pages
    }

    /// Get current memory size in bytes
    pub fn bytes(&self) -> usize {
        (self.pages as usize) * 65536
    }

    /// Check if we can grow by the given number of pages
    pub fn can_grow(&self, additional_pages: u32) -> bool {
        self.pages.saturating_add(additional_pages) <= self.max_pages
    }

    /// Grow memory by the given number of pages
    pub fn grow(&mut self, additional_pages: u32) -> Result<u32> {
        let new_pages = self.pages.saturating_add(additional_pages);
        if new_pages > self.max_pages {
            return Err(RuntimeError::MemoryAccess(format!(
                "Cannot grow memory from {} to {} pages (max: {})",
                self.pages, new_pages, self.max_pages
            )));
        }
        let old_pages = self.pages;
        self.pages = new_pages;
        Ok(old_pages)
    }
}

/// Read a byte slice from WASM memory
pub fn read_bytes(memory: &wasmer::Memory, store: &wasmer::Store, offset: u32, length: u32) -> Result<Vec<u8>> {
    let view = memory.view(store);
    let mut buffer = vec![0u8; length as usize];

    view.read(offset as u64, &mut buffer)
        .map_err(|e| RuntimeError::MemoryAccess(e.to_string()))?;

    Ok(buffer)
}

/// Write bytes to WASM memory
pub fn write_bytes(memory: &wasmer::Memory, store: &wasmer::Store, offset: u32, data: &[u8]) -> Result<()> {
    let view = memory.view(store);

    view.write(offset as u64, data)
        .map_err(|e| RuntimeError::MemoryAccess(e.to_string()))?;

    Ok(())
}

/// Read a u32 from WASM memory
pub fn read_u32(memory: &wasmer::Memory, store: &wasmer::Store, offset: u32) -> Result<u32> {
    let bytes = read_bytes(memory, store, offset, 4)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Read a u64 from WASM memory
pub fn read_u64(memory: &wasmer::Memory, store: &wasmer::Store, offset: u32) -> Result<u64> {
    let bytes = read_bytes(memory, store, offset, 8)?;
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

/// Read a u128 from WASM memory
pub fn read_u128(memory: &wasmer::Memory, store: &wasmer::Store, offset: u32) -> Result<u128> {
    let bytes = read_bytes(memory, store, offset, 16)?;
    Ok(u128::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11],
        bytes[12], bytes[13], bytes[14], bytes[15],
    ]))
}

/// Write a u32 to WASM memory
pub fn write_u32(memory: &wasmer::Memory, store: &wasmer::Store, offset: u32, value: u32) -> Result<()> {
    write_bytes(memory, store, offset, &value.to_le_bytes())
}

/// Write a u64 to WASM memory
pub fn write_u64(memory: &wasmer::Memory, store: &wasmer::Store, offset: u32, value: u64) -> Result<()> {
    write_bytes(memory, store, offset, &value.to_le_bytes())
}

/// Write a u128 to WASM memory
pub fn write_u128(memory: &wasmer::Memory, store: &wasmer::Store, offset: u32, value: u128) -> Result<()> {
    write_bytes(memory, store, offset, &value.to_le_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_manager() {
        let mut mm = MemoryManager::new(1);
        assert_eq!(mm.pages(), 1);
        assert_eq!(mm.bytes(), 65536);

        assert!(mm.can_grow(10));
        let old = mm.grow(10).unwrap();
        assert_eq!(old, 1);
        assert_eq!(mm.pages(), 11);
    }

    #[test]
    fn test_memory_limit() {
        let mut mm = MemoryManager::new(MAX_MEMORY_PAGES);
        assert!(!mm.can_grow(1));
        assert!(mm.grow(1).is_err());
    }
}
