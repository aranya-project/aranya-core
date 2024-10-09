//! The Aranya Policy Virtual Machine

#![allow(unstable_name_collisions)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(any(test, doctest, feature = "std")), no_std)]
#![warn(missing_docs)]

mod data;
mod derive;
mod error;
pub mod ffi;
mod io;
mod machine;
mod scope;
mod stack;
mod tests;

pub use aranya_policy_ast as ast;
pub use aranya_policy_module::*;
pub use data::*;
pub use error::*;
pub use io::*;
pub use machine::*;
pub use stack::*;
