//! The Aranya Policy Language's AST.
//!
//! See [the policy book](https://aranya-project.github.io/policy-book/) for more information on
//! the policy language.

#![allow(unstable_name_collisions)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(any(test, doctest, feature = "std")), no_std)]
#![warn(missing_docs)]

extern crate alloc;

mod ast;
mod span;
pub mod thir;
mod util;

#[cfg(test)]
mod tests;

pub use aranya_policy_text::*;
pub use ast::*;
pub use span::{Span, Spanned};
