#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(clippy::arithmetic_side_effects)]

mod ast;
pub mod compile;
mod compile2;
mod ctx;
mod intern;
//mod dependency_graph;
//mod mir;
//pub mod ir;
//pub mod semantic_analysis;
pub mod hir;
mod symbol_resolution;
mod tests;
mod tracer;
pub mod validate;

pub use compile::*;
pub use tracer::*;
