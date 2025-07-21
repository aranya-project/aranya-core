#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(clippy::arithmetic_side_effects)]

mod error;
mod keywords;
mod markdown;
mod parser;
#[cfg(test)]
mod tests;

pub use aranya_policy_ast as ast;

pub use crate::{
    error::{ParseError, ParseErrorKind},
    markdown::parse_policy_document,
    parser::{
        FfiTypes, parse_expression, parse_ffi_decl, parse_ffi_structs_enums, parse_policy_str,
    },
};
