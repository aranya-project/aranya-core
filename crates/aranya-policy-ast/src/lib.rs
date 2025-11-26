//! The Aranya Policy Language's AST.
//!
//! See [the policy book](https://aranya-project.github.io/policy-book/) for more information on
//! the policy language.

#![allow(unstable_name_collisions)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(any(test, doctest, feature = "std")), no_std)]

// TODO rkyv seems to have trouble with struct-like enum variants, like TypeKind::Result; it issues
// missing-docs warnings, even though the variant and its fields are documented. This warning can't
// be suppressed at the enum (or file) level, so we turn off the warning... Until we find a better
// solution.
//#![warn(missing_docs)]

extern crate alloc;

mod ast;
mod span;
pub mod thir;
mod util;

pub use aranya_policy_text::*;
pub use ast::*;
pub use span::{Span, Spanned};
