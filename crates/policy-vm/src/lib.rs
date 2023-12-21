//! The Aranya Policy Virtual Machine

#![allow(unstable_name_collisions)]
#![cfg_attr(docs, feature(doc_cfg))]
#![cfg_attr(not(any(test, doctest, feature = "std")), no_std)]
#![deny(
    clippy::arithmetic_side_effects,
    clippy::wildcard_imports,
    missing_docs
)]

mod codemap;
mod compile;
mod data;
mod derive;
mod error;
pub mod ffi;
mod instructions;
mod io;
mod machine;
mod stack;
mod tests;

pub use codemap::*;
pub use compile::*;
pub use data::*;
pub use error::*;
pub use instructions::*;
pub use io::*;
pub use machine::*;
pub use policy_ast as ast;
pub use stack::*;
