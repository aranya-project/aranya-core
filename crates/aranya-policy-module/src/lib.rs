//! Policy Module
//!
//! Defines core data types for compiled modules.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(any(test, doctest, feature = "std")), no_std)]
#![warn(missing_docs)]

extern crate alloc;

mod codemap;
mod data;
pub mod ffi;
mod instructions;
mod label;
mod module;
pub mod named;
mod ref_or_box;

pub use aranya_policy_ast as ast;
pub use codemap::*;
pub use data::*;
pub use instructions::*;
pub use label::*;
pub use module::*;
pub use ref_or_box::RefOrBox;
