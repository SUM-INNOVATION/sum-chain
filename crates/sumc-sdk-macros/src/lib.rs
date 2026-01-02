//! Procedural macros for SUM Chain smart contract SDK.
//!
//! Provides attribute macros for contract definitions:
//! - `#[contract]` - Marks a struct as a contract
//! - `#[init]` - Marks the constructor method
//! - `#[call]` - Marks a public method that modifies state
//! - `#[view]` - Marks a public method that only reads state

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput, ItemFn, ItemImpl, ItemStruct};

/// Mark a struct as a smart contract.
///
/// This generates WASM exports and boilerplate for the contract.
///
/// # Example
/// ```ignore
/// #[contract]
/// pub struct Counter {
///     value: u64,
/// }
/// ```
#[proc_macro_attribute]
pub fn contract(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as ItemStruct);
    let name = &input.ident;

    let expanded = quote! {
        #input

        // Generate alloc/dealloc for WASM memory management
        #[no_mangle]
        pub extern "C" fn alloc(size: i32) -> i32 {
            let mut buf = Vec::with_capacity(size as usize);
            let ptr = buf.as_mut_ptr();
            std::mem::forget(buf);
            ptr as i32
        }

        #[no_mangle]
        pub extern "C" fn dealloc(ptr: i32, size: i32) {
            unsafe {
                let _ = Vec::from_raw_parts(ptr as *mut u8, 0, size as usize);
            }
        }
    };

    TokenStream::from(expanded)
}

/// Mark a method as the contract constructor.
///
/// This method is called once when the contract is deployed.
///
/// # Example
/// ```ignore
/// #[init]
/// pub fn new(initial_value: u64) -> Self {
///     Self { value: initial_value }
/// }
/// ```
#[proc_macro_attribute]
pub fn init(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as ItemFn);
    let name = &input.sig.ident;
    let vis = &input.vis;
    let block = &input.block;
    let inputs = &input.sig.inputs;
    let output = &input.sig.output;

    let expanded = quote! {
        #vis fn #name(#inputs) #output #block
    };

    TokenStream::from(expanded)
}

/// Mark a method as a public state-modifying call.
///
/// This method can be invoked by transactions.
///
/// # Example
/// ```ignore
/// #[call]
/// pub fn increment(&mut self) {
///     self.value += 1;
/// }
/// ```
#[proc_macro_attribute]
pub fn call(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as ItemFn);
    let name = &input.sig.ident;
    let vis = &input.vis;
    let block = &input.block;
    let inputs = &input.sig.inputs;
    let output = &input.sig.output;

    // Generate WASM export wrapper
    let export_name = format!("{}", name);

    let expanded = quote! {
        #vis fn #name(#inputs) #output #block
    };

    TokenStream::from(expanded)
}

/// Mark a method as a public read-only view.
///
/// This method can be called without a transaction.
///
/// # Example
/// ```ignore
/// #[view]
/// pub fn get_value(&self) -> u64 {
///     self.value
/// }
/// ```
#[proc_macro_attribute]
pub fn view(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as ItemFn);
    let name = &input.sig.ident;
    let vis = &input.vis;
    let block = &input.block;
    let inputs = &input.sig.inputs;
    let output = &input.sig.output;

    let expanded = quote! {
        #vis fn #name(#inputs) #output #block
    };

    TokenStream::from(expanded)
}

/// Mark a method as payable (can receive Koppa).
///
/// # Example
/// ```ignore
/// #[payable]
/// #[call]
/// pub fn deposit(&mut self) {
///     let amount = env::attached_value();
///     // ...
/// }
/// ```
#[proc_macro_attribute]
pub fn payable(_attr: TokenStream, item: TokenStream) -> TokenStream {
    // Just pass through for now
    item
}
