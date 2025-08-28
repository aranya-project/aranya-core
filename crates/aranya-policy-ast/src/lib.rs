//! The Aranya Policy Language's AST.

#![allow(unstable_name_collisions)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(any(test, doctest, feature = "std")), no_std)]
#![warn(missing_docs)]

extern crate alloc;

mod ast;
mod span;
mod util;

pub use aranya_policy_text::*;
pub use ast::*;
pub use span::{Span, Spanned};
