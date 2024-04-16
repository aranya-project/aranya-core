//! A set of proc macros for requirements tracking.
//!
//! Do not use this crate directly. Use the `rtrack` crate
//! instead.

#![allow(unstable_name_collisions)]
#![cfg_attr(docs, feature(doc_cfg))]
#![warn(clippy::arithmetic_side_effects, missing_docs)]

mod spira;

/// See the `rtrack` crate for documentation.
#[proc_macro_attribute]
#[cfg(feature = "spira")]
pub fn spira(
    attr: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    match option_env!("SPIRA_ENABLED") {
        Some(_) => crate::spira::parse(attr.into(), item.into()).into(),
        None => item,
    }
}
