//! The Aranya policy compiler.
//!
//! See [the policy book](https://aranya-project.github.io/policy-book/) for more information on
//! the policy language.

#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod compile;
mod tests;
mod tracer;
pub mod validate;

pub use compile::*;
pub use tracer::*;
