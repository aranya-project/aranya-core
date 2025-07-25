#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(clippy::arithmetic_side_effects)]

pub mod compile;
mod dependency_graph;
//pub mod ir;
//pub mod semantic_analysis;
mod hir;
//pub mod symbol_resolution;
mod tests;
mod tracer;
pub mod validate;

pub use compile::*;
pub use tracer::*;
