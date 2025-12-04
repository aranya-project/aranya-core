//! The Aranya Policy Virtual Machine
//!
//! See [the policy book](https://aranya-project.github.io/policy-book/) for more information on
//! the policy language.

#![allow(unstable_name_collisions)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(any(test, doctest, feature = "std")), no_std)]
#![warn(missing_docs)]

#[cfg(feature = "bench")]
#[cfg_attr(docsrs, doc(cfg(feature = "bench")))]
mod bench;
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
pub use aranya_policy_ast::{Identifier, Text, ident, text};
pub use aranya_policy_module::*;
#[cfg(feature = "bench")]
#[cfg_attr(docsrs, doc(cfg(feature = "bench")))]
pub use bench::*;
pub use data::*;
pub use error::*;
pub use io::*;
pub use machine::*;
pub use stack::*;
