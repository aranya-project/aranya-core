//! The Aranya Policy Language's AST.

#![allow(unstable_name_collisions)]
#![cfg_attr(docs, feature(doc_cfg))]
#![cfg_attr(not(any(test, doctest, feature = "std")), no_std)]
#![warn(clippy::arithmetic_side_effects, missing_docs)]

mod ast;

pub use ast::*;
