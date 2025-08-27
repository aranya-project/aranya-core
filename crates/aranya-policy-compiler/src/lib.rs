#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(clippy::arithmetic_side_effects)]

mod arena;
mod ast;
pub mod compile;
mod compile2;
mod ctx;
mod depgraph;
mod diag;
mod eval;
mod hir;
mod intern;
mod mir;
mod pass;
mod simplify;
mod symtab;
mod tests;
mod tracer;
mod typecheck;
pub mod validate;
mod verify;

pub use compile::*;
pub use tracer::*;
