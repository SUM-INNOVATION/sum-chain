//! # SUMC SDK
//!
//! Software Development Kit for writing SUM Chain smart contracts in Rust.
//!
//! ## Quick Start
//!
//! ```rust,ignore
//! use sumc_sdk::prelude::*;
//!
//! #[sumc_contract]
//! pub struct MyToken {
//!     name: String,
//!     balances: Map<Address, u128>,
//! }
//!
//! #[sumc_methods]
//! impl MyToken {
//!     #[init]
//!     pub fn new(name: String) -> Self {
//!         Self {
//!             name,
//!             balances: Map::new(),
//!         }
//!     }
//!
//!     pub fn transfer(&mut self, to: Address, amount: u128) -> Result<(), Error> {
//!         let caller = env::caller();
//!         let balance = self.balances.get(&caller).unwrap_or(0);
//!         require!(balance >= amount, "Insufficient balance");
//!
//!         self.balances.insert(caller, balance - amount);
//!         let to_balance = self.balances.get(&to).unwrap_or(0);
//!         self.balances.insert(to, to_balance + amount);
//!
//!         Ok(())
//!     }
//!
//!     #[view]
//!     pub fn balance_of(&self, owner: Address) -> u128 {
//!         self.balances.get(&owner).unwrap_or(0)
//!     }
//! }
//! ```

pub mod env;
pub mod error;
pub mod storage;
pub mod types;

/// Prelude - commonly used items
pub mod prelude {
    pub use crate::env;
    pub use crate::error::{Error, Result};
    pub use crate::storage::{Map, PersistentVec, Set, Value};
    pub use crate::types::{Address, Balance, Hash};
    pub use crate::{emit, log, require};
}

/// Require macro - panics with message if condition is false
#[macro_export]
macro_rules! require {
    ($cond:expr, $msg:expr) => {
        if !$cond {
            $crate::env::abort($msg);
        }
    };
}

/// Emit an event
#[macro_export]
macro_rules! emit {
    ($event:expr) => {
        $crate::env::emit_event(&$event);
    };
}

/// Log a message
#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => {
        $crate::env::log(&format!($($arg)*));
    };
}
