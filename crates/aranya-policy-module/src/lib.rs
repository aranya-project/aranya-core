//! Policy Module
//!
//! Defines core data types for compiled modules.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(any(test, doctest, feature = "std")), no_std)]
#![warn(missing_docs)]
#![warn(clippy::arithmetic_side_effects)]

mod codemap;
mod data;
pub mod ffi;
mod instructions;
mod label;
mod module;
pub mod named;

pub use aranya_policy_ast as ast;
pub use codemap::*;
pub use data::*;
pub use instructions::*;
pub use label::*;
pub use module::*;
