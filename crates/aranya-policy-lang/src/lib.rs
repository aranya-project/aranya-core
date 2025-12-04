//! The Aranya policy language parser.
//!
//! See [the policy book](https://aranya-project.github.io/policy-book/) for more information on
//! the policy language.

#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod lang;
pub use aranya_policy_ast as ast;
