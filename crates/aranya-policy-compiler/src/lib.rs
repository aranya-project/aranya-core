#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(clippy::arithmetic_side_effects)]

pub mod compile;
mod diag;
mod tests;
mod tracer;
pub mod validate;

pub use compile::*;
pub use tracer::*;
