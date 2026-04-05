//! Payload loaders for process injection
//!
//! This module provides loaders that generate shellcode for executing
//! various payload types:
//!
//! - `reflective` - Reflective PE loader for in-memory PE execution
//! - `clr` - CLR hosting loader for .NET assembly execution
//!
//! These loaders generate position-independent shellcode that can be
//! injected into a target process using any injection technique.

pub mod reflective;
pub mod clr;

pub use reflective::generate_reflective_loader;
pub use clr::generate_clr_loader;
