#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(clippy::arithmetic_side_effects)]

pub mod compile;
mod compile2;
mod dependency_graph;
mod mir;
//pub mod ir;
//pub mod semantic_analysis;
mod hir;
mod symbol_resolution;
mod tests;
mod tracer;
pub mod validate;

pub use compile::*;
pub use tracer::*;
