#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(clippy::arithmetic_side_effects)]

mod compile;
mod tests;
mod tracer;

pub use compile::*;
pub use tracer::*;
